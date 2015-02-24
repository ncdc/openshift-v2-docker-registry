package repository

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	kapi "github.com/GoogleCloudPlatform/kubernetes/pkg/api/v1beta3"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/runtime"
	log "github.com/Sirupsen/logrus"
	"github.com/docker/distribution"
	"github.com/docker/distribution/digest"
	"github.com/docker/distribution/manifest"
	"github.com/docker/distribution/registry/storage"
	"github.com/docker/libtrust"
	imageapi "github.com/openshift/origin/pkg/image/api/v1beta1"
)

func init() {
	storage.RegisterRepositoryHandler("openshift", newHandler)
}

type repository struct {
	distribution.Repository

	namespace      string
	repositoryName string
	openshiftAddr  string
	client         *http.Client
}

func newHandler(repo distribution.Repository, options map[string]interface{}) (distribution.Repository, error) {
	caData, _ := options["ca"].(string)
	certData, _ := options["cert"].(string)
	certKeyData, _ := options["certKey"].(string)
	openshiftAddr, _ := options["openshiftAddr"].(string)

	rootPool := x509.NewCertPool()
	pemBlock, _ := pem.Decode([]byte(caData))
	if pemBlock != nil {
		caCert, err := x509.ParseCertificate(pemBlock.Bytes)
		if err != nil {
			log.Warnf("Error parsing CA certificate data: %s", err)
		} else {
			rootPool.AddCert(caCert)
		}
	}
	clientCert, err := tls.X509KeyPair([]byte(certData), []byte(certKeyData))
	if err != nil {
		log.Warnf("Error parsing client certificate data: %s", err)
	} else {
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      rootPool,
			Certificates: []tls.Certificate{clientCert},
		},
	}
	client := &http.Client{Transport: transport}

	nameParts := strings.Split(repo.Name(), "/")

	return &repository{
		Repository:     repo,
		namespace:      nameParts[0],
		repositoryName: nameParts[1],
		openshiftAddr:  openshiftAddr,
		client:         client,
	}, nil
}

func (r *repository) Manifests() distribution.ManifestService {
	return r
}

func (r *repository) getImageRepository() (*imageapi.ImageRepository, error) {
	// <-----r.openshiftAddr-------->
	// https://<server>/osapi/v1beta1/imageRepositories/<repo>?namespace=<ns>
	tagUrl := fmt.Sprintf("%s/imageRepositories/%s?namespace=%s", r.openshiftAddr, r.repositoryName, r.namespace)
	resp, err := r.client.Get(tagUrl)
	if err != nil {
		return nil, fmt.Errorf("Error querying OpenShift for image repository: %s", err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Error reading OpenShift image repository response body: %s", err)
	}
	/*
		var imageRepository map[string]interface{}
		err = json.Unmarshal(body, &imageRepository)
		if err != nil {
			return []string{}, fmt.Errorf("Error parsing ImageRepository: %s", err)
		}
		tagMap, ok := imageRepository["tags"].(map[string]interface{})
		if !ok {
			return []string{}, fmt.Errorf("Error parsing tags: %q", imageRepository["tags"])
		}
		tags := []string{}
		for tag, _ := range tagMap {
			tags = append(tags, tag)
		}
	*/
	var imageRepository imageapi.ImageRepository
	err = json.Unmarshal(body, &imageRepository)
	if err != nil {
		return nil, fmt.Errorf("Error parsing ImageRepository: %s", err)
	}
	return &imageRepository, nil
}

func (r *repository) getImage(dgst digest.Digest) (*imageapi.Image, error) {
	// <-----r.openshiftAddr-------->
	// https://<server>/osapi/v1beta1/images/<repo>?namespace=<ns>
	// TODO make images global, not namespaced?
	// TODO or should we change them so they're under repo, like in Docker?
	imageUrl := fmt.Sprintf("%s/images/%s?namespace=%s", r.openshiftAddr, dgst.String(), r.namespace)
	resp, err := r.client.Get(imageUrl)
	if err != nil {
		return nil, fmt.Errorf("Error querying OpenShift for image: %s", err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Error reading OpenShift image response body: %s", err)
	}
	var image imageapi.Image
	err = json.Unmarshal(body, &image)
	if err != nil {
		return nil, fmt.Errorf("Error parsing image: %s", err)
	}
	return &image, nil
}

// Tags lists the tags under the named repository.
func (r *repository) Tags() ([]string, error) {
	imageRepository, err := r.getImageRepository()
	if err != nil {
		return []string{}, nil
	}
	tags := []string{}
	for tag, _ := range imageRepository.Tags {
		tags = append(tags, tag)
	}

	return tags, nil
}

// Exists returns true if the manifest exists.
func (r *repository) Exists(tag string) (bool, error) {
	imageRepository, err := r.getImageRepository()
	if err != nil {
		return false, err
	}
	_, found := imageRepository.Tags[tag]
	return found, nil
}

// Get retrieves the named manifest, if it exists.
func (r *repository) Get(tag string) (*manifest.SignedManifest, error) {
	imageRepository, err := r.getImageRepository()
	if err != nil {
		return nil, err
	}

	dgst, err := digest.ParseDigest(imageRepository.Tags[tag])
	if err != nil {
		return nil, err
	}

	// Fetch the signatures for the manifest
	signatures, err := r.Signatures().Get(dgst)
	if err != nil {
		return nil, err
	}

	image, err := r.getImage(dgst)
	if err != nil {
		return nil, err
	}

	jsig, err := libtrust.NewJSONSignature([]byte(image.RawManifest), signatures...)
	if err != nil {
		return nil, err
	}

	// Extract the pretty JWS
	raw, err := jsig.PrettySignature("signatures")
	if err != nil {
		return nil, err
	}

	var sm manifest.SignedManifest
	if err := json.Unmarshal(raw, &sm); err != nil {
		return nil, err
	}
	return &sm, err
}

// Put creates or updates the named manifest.
// Put(tag string, manifest *manifest.SignedManifest) (digest.Digest, error)
func (r *repository) Put(tag string, manifest *manifest.SignedManifest) error {
	log.Debugln("Getting manifest payload")
	// Resolve the payload in the manifest.
	payload, err := manifest.Payload()
	if err != nil {
		return err
	}

	// Calculate digest
	log.Debugln("Calculating digest")
	dgst, err := digest.FromBytes(payload)
	if err != nil {
		return err
	}
	log.Debugf("Digest = %s", dgst.String())

	// Upload to openshift
	irm := imageapi.ImageRepositoryMapping{
		TypeMeta: kapi.TypeMeta{
			APIVersion: "v1beta1",
			Kind:       "ImageRepositoryMapping",
		},
		ObjectMeta: kapi.ObjectMeta{
			Namespace: r.namespace,
			Name:      r.repositoryName,
		},
		Tag: tag,
		Image: imageapi.Image{
			TypeMeta: kapi.TypeMeta{
				APIVersion: "v1beta1",
				Kind:       "Image",
			},
			ObjectMeta: kapi.ObjectMeta{
				Name: dgst.String(),
			},
			DockerImageReference: "foo/bar:latest",
			DockerImageMetadata:  runtime.RawExtension{[]byte("{}")},
			RawManifest:          string(payload),
		},
	}

	log.Debugln("Marshaling IRM to json")
	irmBytes, err := json.Marshal(irm)
	if err != nil {
		log.Errorf("Error marshaling IRM to json: %s", err)
		return err
	}

	irmUrl := fmt.Sprintf("%s/imageRepositoryMappings?namespace=%s", r.openshiftAddr, r.namespace)
	log.Debugf("POST to %s", irmUrl)
	resp, err := r.client.Post(irmUrl, "application/json", bytes.NewReader(irmBytes))
	if err != nil {
		return err
	}
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	log.Debugf("resp body: %s", string(respBody))

	// Grab each json signature and store them.
	signatures, err := manifest.Signatures()
	if err != nil {
		return err
	}

	for _, signature := range signatures {
		if err := r.Signatures().Put(dgst, signature); err != nil {
			return err
		}
	}

	return nil
}

// Delete removes the named manifest, if it exists.
func (r *repository) Delete(tag string) error {
	return nil
}
