// Package gs provides a restic backend for Google Cloud Storage.
package gs

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"hash"
	"io"
	"net/http"
	"os"
	"path"
	"strings"

	"cloud.google.com/go/storage"
	"github.com/pkg/errors"
	"github.com/restic/restic/internal/backend"
	"github.com/restic/restic/internal/backend/layout"
	"github.com/restic/restic/internal/backend/location"
	"github.com/restic/restic/internal/debug"
	"github.com/restic/restic/internal/restic"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

// Backend stores data in a GCS bucket.
//
// The service account used to access the bucket must have these permissions:
//   - storage.objects.create
//   - storage.objects.delete
//   - storage.objects.get
//   - storage.objects.list
type Backend struct {
	gcsClient    *storage.Client
	projectID    string
	connections  uint
	bucketName   string
	region       string
	bucket       *storage.BucketHandle
	prefix       string
	listMaxItems int
	layout.Layout
	encryptKey  gsKeyTuple
	decryptKeys map[string][]byte
}

type gsKeyTuple struct {
	Key    []byte
	KeySha string
}

// Ensure that *Backend implements restic.Backend.
var _ restic.Backend = &Backend{}

func NewFactory() location.Factory {
	return location.NewHTTPBackendFactory("gs", ParseConfig, location.NoPassword, Create, Open)
}

func getStorageClient(rt http.RoundTripper) (*storage.Client, error) {
	// create a new HTTP client
	httpClient := &http.Client{
		Transport: rt,
	}

	// create a new context with the HTTP client stored at the oauth2.HTTPClient key
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, httpClient)

	var ts oauth2.TokenSource
	if token := os.Getenv("GOOGLE_ACCESS_TOKEN"); token != "" {
		ts = oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: token,
			TokenType:   "Bearer",
		})
	} else {
		var err error
		ts, err = google.DefaultTokenSource(ctx, storage.ScopeReadWrite)
		if err != nil {
			return nil, err
		}
	}

	oauthClient := oauth2.NewClient(ctx, ts)

	gcsClient, err := storage.NewClient(ctx, option.WithHTTPClient(oauthClient))
	if err != nil {
		return nil, err
	}

	return gcsClient, nil
}

func (be *Backend) bucketExists(ctx context.Context, bucket *storage.BucketHandle) (bool, error) {
	_, err := bucket.Attrs(ctx)
	if err == storage.ErrBucketNotExist {
		return false, nil
	}
	return err == nil, err
}

const defaultListMaxItems = 1000

func open(cfg Config, rt http.RoundTripper) (*Backend, error) {
	debug.Log("open, config %#v", cfg)

	gcsClient, err := getStorageClient(rt)
	if err != nil {
		return nil, errors.Wrap(err, "getStorageClient")
	}

	//process keys
	var encrypt_key gsKeyTuple
	if cfg.EncryptionKey != "" {
		encrypt_key.Key, err = base64.StdEncoding.DecodeString(cfg.EncryptionKey)
		if err != nil {
			err = errors.Errorf("Google Storage customer-supplied encryption key not Base64.")
			return nil, err
		}
		if len(encrypt_key.Key) != 32 {
			err = errors.Errorf("Google Storage customer-supplied encryption key not 256 bits long.")
			return nil, err
		}
		sha := sha256.Sum256(encrypt_key.Key)
		encrypt_key.KeySha = base64.StdEncoding.EncodeToString(sha[:])
	}

	var decrypt_keys = make(map[string][]byte, 100)
	if cfg.DecryptionKeys != nil {
		for _, key := range cfg.DecryptionKeys {
			var gsDecryptKeyEnv string = key
			if gsDecryptKeyEnv != "" {
				var gsKeyByte []byte
				var gsKeyShaString string
				var err error

				gsKeyByte, err = base64.StdEncoding.DecodeString(gsDecryptKeyEnv)
				if err != nil {
					err = errors.Errorf("Google Storage customer-supplied decryption key not Base64.")
					return nil, err
				}
				if len(gsKeyByte) != 32 {
					err = errors.Errorf("Google Storage customer-supplied decryption key not 256 bits long.")
					return nil, err
				}
				sha := sha256.Sum256(gsKeyByte)
				gsKeyShaString = base64.StdEncoding.EncodeToString(sha[:])
				decrypt_keys[gsKeyShaString] = gsKeyByte
			}
		}
	}

	be := &Backend{
		gcsClient:   gcsClient,
		projectID:   cfg.ProjectID,
		connections: cfg.Connections,
		bucketName:  cfg.Bucket,
		region:      cfg.Region,
		bucket:      gcsClient.Bucket(cfg.Bucket),
		prefix:      cfg.Prefix,
		encryptKey:  encrypt_key,
		decryptKeys: decrypt_keys,
		Layout: &layout.DefaultLayout{
			Path: cfg.Prefix,
			Join: path.Join,
		},
		listMaxItems: defaultListMaxItems,
	}

	return be, nil
}

// Open opens the gs backend at the specified bucket.
func Open(_ context.Context, cfg Config, rt http.RoundTripper) (restic.Backend, error) {
	return open(cfg, rt)
}

// Create opens the gs backend at the specified bucket and attempts to creates
// the bucket if it does not exist yet.
//
// The service account must have the "storage.buckets.create" permission to
// create a bucket the does not yet exist.
func Create(ctx context.Context, cfg Config, rt http.RoundTripper) (restic.Backend, error) {
	be, err := open(cfg, rt)
	if err != nil {
		return nil, errors.Wrap(err, "open")
	}

	// Try to determine if the bucket exists. If it does not, try to create it.
	exists, err := be.bucketExists(ctx, be.bucket)
	if err != nil {
		if e, ok := err.(*googleapi.Error); ok && e.Code == http.StatusForbidden {
			// the bucket might exist!
			// however, the client doesn't have storage.bucket.get permission
			return be, nil
		}
		return nil, errors.Wrap(err, "service.Buckets.Get")
	}

	if !exists {
		bucketAttrs := &storage.BucketAttrs{
			Location: cfg.Region,
		}
		// Bucket doesn't exist, try to create it.
		if err := be.bucket.Create(ctx, be.projectID, bucketAttrs); err != nil {
			// Always an error, as the bucket definitely doesn't exist.
			return nil, errors.Wrap(err, "service.Buckets.Insert")
		}

	}

	return be, nil
}

// SetListMaxItems sets the number of list items to load per request.
func (be *Backend) SetListMaxItems(i int) {
	be.listMaxItems = i
}

// IsNotExist returns true if the error is caused by a not existing file.
func (be *Backend) IsNotExist(err error) bool {
	return errors.Is(err, storage.ErrObjectNotExist)
}

// Join combines path components with slashes.
func (be *Backend) Join(p ...string) string {
	return path.Join(p...)
}

func (be *Backend) Connections() uint {
	return be.connections
}

// Location returns this backend's location (the bucket name).
func (be *Backend) Location() string {
	return be.Join(be.bucketName, be.prefix)
}

// Hasher may return a hash function for calculating a content hash for the backend
func (be *Backend) Hasher() hash.Hash {
	return md5.New()
}

// HasAtomicReplace returns whether Save() can atomically replace files
func (be *Backend) HasAtomicReplace() bool {
	return true
}

// Path returns the path in the bucket that is used for this backend.
func (be *Backend) Path() string {
	return be.prefix
}

// Save stores data in the backend at the handle.
func (be *Backend) Save(ctx context.Context, h restic.Handle, rd restic.RewindReader) error {
	objName := be.Filename(h)

	// Set chunk size to zero to disable resumable uploads.
	//
	// With a non-zero chunk size (the default is
	// googleapi.DefaultUploadChunkSize, 8MB), Insert will buffer data from
	// rd in chunks of this size so it can upload these chunks in
	// individual requests.
	//
	// This chunking allows the library to automatically handle network
	// interruptions and re-upload only the last chunk rather than the full
	// file.
	//
	// Unfortunately, this buffering doesn't play nicely with
	// --limit-upload, which applies a rate limit to rd. This rate limit
	// ends up only limiting the read from rd into the buffer rather than
	// the network traffic itself. This results in poor network rate limit
	// behavior, where individual chunks are written to the network at full
	// bandwidth for several seconds, followed by several seconds of no
	// network traffic as the next chunk is read through the rate limiter.
	//
	// By disabling chunking, rd is passed further down the request stack,
	// where there is less (but some) buffering, which ultimately results
	// in better rate limiting behavior.
	//
	// restic typically writes small blobs (4MB-30MB), so the resumable
	// uploads are not providing significant benefit anyways.

	var w *storage.Writer
	bucket_object := be.bucket.Object(objName)
	if len(be.encryptKey.Key) != 0 {
		w = bucket_object.Key(be.encryptKey.Key).NewWriter(ctx)
	} else {
		w = bucket_object.NewWriter(ctx)
	}
	w.ChunkSize = 0
	w.MD5 = rd.Hash()
	wbytes, err := io.Copy(w, rd)
	cerr := w.Close()
	if err == nil {
		err = cerr
	}

	if err != nil {
		return errors.Wrap(err, "service.Objects.Insert")
	}

	// sanity check
	if wbytes != rd.Length() {
		return errors.Errorf("wrote %d bytes instead of the expected %d bytes", wbytes, rd.Length())
	}
	return nil
}

// Load runs fn with a reader that yields the contents of the file at h at the
// given offset.
func (be *Backend) Load(ctx context.Context, h restic.Handle, length int, offset int64, fn func(rd io.Reader) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	return backend.DefaultLoad(ctx, h, length, offset, be.openReader, fn)
}

func (be *Backend) openReader(ctx context.Context, h restic.Handle, length int, offset int64) (io.ReadCloser, error) {
	var err error
	debug.Log("Load %v, length %v, offset %v from %v", h, length, offset, be.Filename(h))
	if err = h.Valid(); err != nil {
		return nil, err
	}

	if offset < 0 {
		return nil, errors.New("offset is negative")
	}

	if length < 0 {
		return nil, errors.Errorf("invalid length %d", length)
	}
	if length == 0 {
		// negative length indicates read till end to GCS lib
		length = -1
	}

	objName := be.Filename(h)

	//https://cloud.google.com/storage/docs/encryption/using-customer-supplied-keys
	err = nil
	bucketObject := be.bucket.Object(objName)
	objectArrts, _ := bucketObject.Attrs(ctx)
	objectKeySha := objectArrts.CustomerKeySHA256
	var cryptoKey []byte
	var rangeReader *storage.Reader

	if objectKeySha != "" {

		//try current key first
		if objectKeySha == be.encryptKey.KeySha {
			cryptoKey = be.encryptKey.Key
		}
		//fallback to list of old keys
		if cryptoKey == nil {
			cryptoKey = be.decryptKeys[objectKeySha]
		}
		//none of the supplied keys match object key
		if cryptoKey == nil {
			err = errors.New(("Google Storage customer-supplied encryption keys failed."))
		}
		if err == nil {
			rangeReader, err = bucketObject.Key(cryptoKey).NewRangeReader(ctx, offset, int64(length))
		}
	} else {
		rangeReader, err = bucketObject.NewRangeReader(ctx, offset, int64(length))

	}

	if err != nil {
		return nil, err
	}

	return rangeReader, err
}

// Stat returns information about a blob.
func (be *Backend) Stat(ctx context.Context, h restic.Handle) (bi restic.FileInfo, err error) {
	objName := be.Filename(h)

	attr, err := be.bucket.Object(objName).Attrs(ctx)

	if err != nil {
		return restic.FileInfo{}, errors.Wrap(err, "service.Objects.Get")
	}

	return restic.FileInfo{Size: attr.Size, Name: h.Name}, nil
}

// Remove removes the blob with the given name and type.
func (be *Backend) Remove(ctx context.Context, h restic.Handle) error {
	objName := be.Filename(h)

	err := be.bucket.Object(objName).Delete(ctx)

	if be.IsNotExist(err) {
		err = nil
	}

	return errors.Wrap(err, "client.RemoveObject")
}

// List runs fn for each file in the backend which has the type t. When an
// error occurs (or fn returns an error), List stops and returns it.
func (be *Backend) List(ctx context.Context, t restic.FileType, fn func(restic.FileInfo) error) error {
	prefix, _ := be.Basedir(t)

	// make sure prefix ends with a slash
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	itr := be.bucket.Objects(ctx, &storage.Query{Prefix: prefix})

	for {
		attrs, err := itr.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return err
		}
		m := strings.TrimPrefix(attrs.Name, prefix)
		if m == "" {
			continue
		}

		fi := restic.FileInfo{
			Name: path.Base(m),
			Size: int64(attrs.Size),
		}

		err = fn(fi)
		if err != nil {
			return err
		}

		if ctx.Err() != nil {
			return ctx.Err()
		}
	}

	return ctx.Err()
}

// Delete removes all restic keys in the bucket. It will not remove the bucket itself.
func (be *Backend) Delete(ctx context.Context) error {
	return backend.DefaultDelete(ctx, be)
}

// Close does nothing.
func (be *Backend) Close() error { return nil }
