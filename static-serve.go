package static

import (
	"compress/gzip"
	"crypto/sha1"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"
	"unsafe"
)

const (
	_acceptEncoding  = "Accept-Encoding"
	_contentEncoding = "Content-Encoding"
	_contentType     = "Content-Type"
	_gzip            = "gzip"
	_eTag            = "Etag"
	_ifNoneMatch     = "If-None-Match"
	_msie6           = "MSIE 6"
	_userAgent       = "User-Agent"

	deadline    = 10 * time.Second
	respBufSize = 2048

	bytesSizeInPool   = 512
	eTagClearSchedule = 5 * time.Minute

	pathSeparatorNeedsConversion = os.PathSeparator != '/'

	_dotHtml          = ".html"
	_dotGz            = ".gz"
	_home             = "home"
	_homeDotHtml      = _home + _dotHtml
	_homeDotHtmlDotGz = _homeDotHtml + _dotGz
)

var (
	htmlContentHeader = []string{"text/html; charset=utf-8"}
	cssContentHeader  = []string{"text/css; charset=utf-8"}
	jsContentHeader   = []string{"application/x-javascript"}
	jsonContentHeader = []string{"application/json"}
	xmlContentHeader  = []string{"text/xml; charset=utf-8"}
	gifContentHeader  = []string{"image/gif"}
	jpgContentHeader  = []string{"image/jpeg"}
	pdfContentHeader  = []string{"application/pdf"}
	pngContentHeader  = []string{"image/png"}
	icoContentHeader  = []string{"image/x-icon"}

	gzipHeader = []string{_gzip}
)

func NewStaticServer(
	siteRoot string,
	//	resdir, indexName string,
	//	isAbsolute bool,
) (*StaticServe, error) {
	/*
		const sep = "/\\"

			resdir = strings.TrimSpace(resdir)
			resdir = strings.Trim(resdir, sep)

			if len(resdir) == 0 || strings.ContainsAny(resdir, sep) {
				return nil, fmt.Errorf("Invalid resources directory name")
			}

		indexName = strings.TrimSpace(indexName)
		if (len(indexName) != 0 && path.Ext(indexName) != _dotHtml) ||
			strings.ContainsAny(indexName, sep) {
			return nil, fmt.Errorf("Invalid index page name")
		}
	*/

	// TODO: Verify workDir
	var execPath, err = os.Executable()
	if err != nil {
		return nil, err
	}

	var workDir = filepath.Dir(execPath)

	if !strings.HasPrefix(siteRoot, workDir) {
		return nil, fmt.Errorf(
			"unable to find site root in executable directory\nsite root: %q\nwork dir: %q", 
			siteRoot,
			workDir,
		)
	}

	return &StaticServe{
		siteRoot: siteRoot,
		//	resDir:             resdir,
		//		indexName: indexName,
		//	resDirIsAbsolute:   isAbsolute,
		//		indexNameIsDirName: indexName == "",
	}, nil
}

type StaticServe struct {
	siteRoot string
	//	resDir             string
	//	indexName string
	//	resDirIsAbsolute   bool
	//	indexNameIsDirName bool
}

func (s *StaticServe) failWith(w http.ResponseWriter, r *http.Request, code int) {
	// TODO: Implement this for real
	http.NotFound(w, r)
}

var pathSlices sync.Pool

func init() {
	pathSlices.New = func() interface{} {
		return make([]byte, 0, 8)
	}
}

func cleanAndChop(
	pth string,
) (leading, base, page, ext, zipExt string, mime []string, err error) {

	const _unauthHiddenFileMsg = "Unauthorized directory or file"

	var errIfDot = func(c byte) bool {
		// A leading dot on any part of a path is prohibited.
		if c == '.' {
			err = fmt.Errorf(_unauthHiddenFileMsg)
			return true
		}
		return false
	}

	// remove leading slashes
	for len(pth) != 0 && pth[0] == '/' {
		pth = pth[1:]
	}

	if len(pth) == 0 {
		leading = ""
		base = ""
		page = _home
		ext = _dotHtml
		zipExt = _dotGz
		mime = htmlContentHeader
		return
	}

	if errIfDot(pth[0]) {
		return
	}

	defer func() {
		if pathSeparatorNeedsConversion {
			// Make remainder of path os-specific
			var leadingBytes = strToBytes(leading)

			for i := range leadingBytes {
				if leadingBytes[i] == '/' {
					leadingBytes[i] = os.PathSeparator

					// Check for hidden directories.
					// i+1 is safe because 'leading' never ends on a '/'
					if errIfDot(leadingBytes[i+1]) {
						return
					}
				}
			}
		} else {
			// Just check for hidden directories
			for i := range leading {
				// i+1 is safe because 'leading' never ends on a '/'
				if leading[i] == '/' && errIfDot(leading[i+1]) {
					return
				}
			}
		}
	}()

	var hadTrailingSlash = false

	// remove trailing slashes
	last := len(pth) - 1
	for pth[last] == '/' {
		hadTrailingSlash = true
		last--
	}
	if hadTrailingSlash {
		pth = pth[0 : last+1]
	}

	// Get base, and maybe extension
	var dotIndex = -1
	for last != -1 && pth[last] != '/' {
		if pth[last] == '.' && dotIndex == -1 {
			// There could be multiple dots, so grab the one closest to the end
			dotIndex = last
		}
		last--
	}

	if hadTrailingSlash || dotIndex == -1 || dotIndex == len(pth)-1 {
		// It was (or is considered) a directory
		base = pth[last+1:]
		page = base
		ext = _dotHtml
		zipExt = _dotGz
		mime = htmlContentHeader

		if errIfDot(base[0]) {
			return
		}

		if last == -1 {
			return
		}

		for pth[last] == '/' {
			last--
		}

		leading = pth[0 : last+1]

		return
	}

	// Not a dir, so process the parts with the known extension info
	ext = pth[dotIndex:]
	page = pth[last+1 : len(pth)-len(ext)]

	if errIfDot(page[0]) {
		return
	}

	switch ext[1:] {
	default: // Treat as directory that serves its like-named .html file
		base = pth[last+1:]
		page = base
		ext = _dotHtml
		zipExt = _dotGz
		mime = htmlContentHeader

		goto LEADING

	case "gif":
		mime = gifContentHeader
	case "jpg":
		mime = jpgContentHeader
	case "png":
		mime = pngContentHeader
	case "pdf":
		mime = pdfContentHeader
	case "ico":
		mime = icoContentHeader

	case "html":
		mime, zipExt = htmlContentHeader, _dotGz
	case "css":
		mime, zipExt = cssContentHeader, _dotGz
	case "js":
		mime, zipExt = jsContentHeader, _dotGz
	case "json":
		mime, zipExt = jsonContentHeader, _dotGz
	case "xml":
		mime, zipExt = xmlContentHeader, _dotGz
	}

	if last == -1 {
		return
	}

	for pth[last] == '/' {
		last--
	}

	pth = pth[0 : last+1]

	for last != -1 && pth[last] != '/' {
		last--
	}

	base = pth[last+1:]

LEADING:
	if errIfDot(base[0]) {
		return
	}

	if last == -1 {
		return
	}

	for pth[last] == '/' {
		last--
	}

	leading = pth[0 : last+1]

	return
}

func (s *StaticServe) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET", "POST": // Do nothing
	default:
		s.failWith(w, r, 0)
		return
	}

	var etg = r.Header.Get(_ifNoneMatch)

	if etg != "" {
		var _, ok = eTagMap.Load(etg)
		if ok {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}

	var leading, base, page, ext, zipExt, mime, err = cleanAndChop(r.URL.Path)

	if logErr(err) {
		s.failWith(w, r, 0)
		return
	}

	var doGzip = len(zipExt) != 0
	var respHdrs = w.Header()
	respHdrs[_contentType] = mime

	//PREPARE:

	if doGzip && !strings.Contains(r.Header.Get(_acceptEncoding), _gzip) {
		doGzip = false
		zipExt = ""
	}

	// TODO: Since the s.siteRoot never changes,
	//		I should keep that as part of the cached memory.

	var fullPathBytes = pathSlices.Get().([]byte)

	var hasLeading, hasBase = len(leading) != 0, len(base) != 0

	var ln = len(s.siteRoot) + len(leading) +
		len(base) + len(page) + len(ext) + len(zipExt)

	if hasLeading && hasBase {
		ln += 2
	} else if hasLeading || hasBase {
		ln += 1
	}

	if cap(fullPathBytes) < ln {
		fullPathBytes = make([]byte, 0, ln)
	}

	fullPathBytes = append(fullPathBytes, s.siteRoot...)

	if hasLeading {
		// Avoid extra path separator when 'leading' is empty
		fullPathBytes = append(append(
			fullPathBytes, leading...), os.PathSeparator,
		)
	}

	if hasBase {
		// Avoid extra path separator when 'base' is empty
		fullPathBytes = append(append(
			fullPathBytes, base...), os.PathSeparator,
		)
	}

	fullPathBytes = append(append(append(
		fullPathBytes, page...), ext...), zipExt...,
	)

	defer pathSlices.Put(fullPathBytes[0:0])

	// Serves a static file from the filesystem for the given path.
	// If the content type can be zipped, it first looks for a pre-zipped version
	// of the file. If none is found, it attempts to zip and save the file.

	var pth = bytesToStr(fullPathBytes)
	var pathNoGz = pth[0 : len(pth)-len(zipExt)]

	var buf = bytesPool.Get().(*[bytesSizeInPool]byte)
	defer bytesPool.Put(buf)

	file, err := os.Open(pth)
	if err == nil {
		goto SEND_FILE
	}

	if !doGzip {
		s.failWith(w, r, 0) // No original & no gzipping, so 404.
		return
	}

	// Gzip allowed, but no gzip file, so try with the original path

	file, err = os.Open(pathNoGz)
	if err != nil {
		s.failWith(w, r, 0) // No original, so 404.
		return
	}

	// We have the original, non-zipped file, so zip and serve it.
	// If zipping fails, serve the non-zipped file.

	// Gzip the file to a new file and close, reopen, and send it.

	if gzFile, err := os.Create(pth); logErr(err) {
		doGzip = false
		goto SEND_FILE // Original file is still open, so send that one

	} else {
		zipper, err := gzip.NewWriterLevel(gzFile, gzip.BestCompression)

		if logErr(err) {
			doGzip = false
			loggingCloser(gzFile, pth)
			loggingFileRemover(pth)
			goto SEND_FILE // Original file is still open, so send that one
		}

		// TODO: Maybe I should write to two different destinations
		//			so that I don't need to re-open the gzip file

		tw := io.TeeReader(file, zipper)
		for err == nil {
			_, err = tw.Read(buf[:])
		}

		loggingCloser(zipper, "")  // Flush the gzipper...
		loggingCloser(gzFile, pth) // ...then close the new file...
		loggingCloser(file, pth)   // ...and close the original

		if logErr(err) {
			goto REOPEN
		}

		// Open gzip file
		if file, err = os.Open(pth); logErr(err) {
			goto REOPEN
		}

		goto SEND_FILE

	REOPEN:
		doGzip = false

		// Zipping failed, so grab the original again
		if file, err = os.Open(pathNoGz); logErr(err) {
			// Unable to reopen file
			http.Error(
				w, "Internal server error", http.StatusInternalServerError,
			)
			return
		}
	}

SEND_FILE:
	defer loggingCloser(file, pth)

	if doGzip {
		respHdrs[_contentEncoding] = gzipHeader
	}

	stat, err := file.Stat()
	if logErr(err) {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if stat.IsDir() { // Make sure the file isn't a directory
		http.Error(w, "Not authorized", http.StatusUnauthorized)
		return
	}

	n := copy(buf[:], pathNoGz)
	sum := sha1.Sum(buf[0:n])

	// Format of etag relates to the following indexes:
	//   "               	0
	//   shasum          	1-40
	//   .				 				41
	//   64-bit mod time 	42-49
	//   64-bit size	 		50-57
	//   "				 				58

	// etagBuf := (*[59]byte)(buf[0:59])

	buf[0] = '"'


	writeHexPair((*[2]byte)(buf[1:]), sum[0])
	writeHexPair((*[2]byte)(buf[3:]), sum[1])
	writeHexPair((*[2]byte)(buf[5:]), sum[2])
	writeHexPair((*[2]byte)(buf[7:]), sum[3])
	writeHexPair((*[2]byte)(buf[9:]), sum[4])
	writeHexPair((*[2]byte)(buf[11:]), sum[5])
	writeHexPair((*[2]byte)(buf[13:]), sum[6])
	writeHexPair((*[2]byte)(buf[15:]), sum[7])
	writeHexPair((*[2]byte)(buf[17:]), sum[8])
	writeHexPair((*[2]byte)(buf[19:]), sum[9])
	writeHexPair((*[2]byte)(buf[21:]), sum[10])
	writeHexPair((*[2]byte)(buf[23:]), sum[11])
	writeHexPair((*[2]byte)(buf[25:]), sum[12])
	writeHexPair((*[2]byte)(buf[27:]), sum[13])
	writeHexPair((*[2]byte)(buf[29:]), sum[14])
	writeHexPair((*[2]byte)(buf[31:]), sum[15])
	writeHexPair((*[2]byte)(buf[33:]), sum[16])
	writeHexPair((*[2]byte)(buf[35:]), sum[17])
	writeHexPair((*[2]byte)(buf[37:]), sum[18])
	writeHexPair((*[2]byte)(buf[39:]), sum[19])

	// buf[1], buf[2] = hex[sum[0]>>4], hex[sum[0]&0xF]
	// buf[3], buf[4] = hex[sum[1]>>4], hex[sum[1]&0xF]
	// buf[5], buf[6] = hex[sum[2]>>4], hex[sum[2]&0xF]
	// buf[7], buf[8] = hex[sum[3]>>4], hex[sum[3]&0xF]
	// buf[9], buf[10] = hex[sum[4]>>4], hex[sum[4]&0xF]
	// buf[11], buf[12] = hex[sum[5]>>4], hex[sum[5]&0xF]
	// buf[13], buf[14] = hex[sum[6]>>4], hex[sum[6]&0xF]
	// buf[15], buf[16] = hex[sum[7]>>4], hex[sum[7]&0xF]
	// buf[17], buf[18] = hex[sum[8]>>4], hex[sum[8]&0xF]
	// buf[19], buf[20] = hex[sum[9]>>4], hex[sum[9]&0xF]
	// buf[21], buf[22] = hex[sum[10]>>4], hex[sum[10]&0xF]
	// buf[23], buf[24] = hex[sum[11]>>4], hex[sum[11]&0xF]
	// buf[25], buf[26] = hex[sum[12]>>4], hex[sum[12]&0xF]
	// buf[27], buf[28] = hex[sum[13]>>4], hex[sum[13]&0xF]
	// buf[29], buf[30] = hex[sum[14]>>4], hex[sum[14]&0xF]
	// buf[31], buf[32] = hex[sum[15]>>4], hex[sum[15]&0xF]
	// buf[33], buf[34] = hex[sum[16]>>4], hex[sum[16]&0xF]
	// buf[35], buf[36] = hex[sum[17]>>4], hex[sum[17]&0xF]
	// buf[37], buf[38] = hex[sum[18]>>4], hex[sum[18]&0xF]
	// buf[39], buf[40] = hex[sum[19]>>4], hex[sum[19]&0xF]

	mod := stat.ModTime()

	buf[41] = '.'
	int64ToHex8(buf[42:50], mod.Unix())
	int64ToHex8(buf[50:58], stat.Size())
	buf[58] = '"'

	var dataStr = string(buf[0:59]) // need a copy of the reusable buffer

	eTagMap.Store(dataStr, struct{}{})

	if etg == dataStr[1:len(dataStr)-1] {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Header().Set(_eTag, dataStr)
	http.ServeContent(w, r, pth, mod, file)
}

var eTagMap sync.Map

// The eTagMap gets cleared on an interval just in case some resource was
// updated. This just means that the tag will be regenerated in the map at
// its next request. If nothing changed, the tag will be the same.
func init() {
	var firstInterval = int64(eTagClearSchedule) - (time.Now().UnixNano() % int64(eTagClearSchedule))

	_ = time.AfterFunc(time.Duration(firstInterval), clearETagMap)
}

func clearETagMap() {
	eTagMap.Range(func(k, _ interface{}) bool {
		eTagMap.Delete(k)
		return true
	})

	_ = time.AfterFunc(eTagClearSchedule, clearETagMap)
}

var bytesPool = sync.Pool{
	New: func() interface{} {
		return &[bytesSizeInPool]byte{}
	},
}

// Writes from byte 0 through 7.
func int64ToHex8(buf []byte, n int64) {
	for i := 6; i > -1; i -= 2 {
		if n != 0 {
			buf[i], buf[i+1] = toHex(byte(n)>>4), toHex(byte(n)&0xF)
			n >>= 8
		} else {
			buf[i], buf[i+1] = 0, 0
		}
	}
}

const hex = "0123456789ABCDEF"

func toHex(b byte) byte {
	return hex[b]
}

func writeHexPair(buf *[2]byte, b byte) {
//func writeHexPair(buf []byte, b byte) {
	buf[0], buf[1] = hex[b>>4], hex[b&0xF]
}

func logErr(err error) bool {
	if err != nil && err != io.EOF {
		log.Println(err.Error())
		return true
	}
	return false
}

func loggingFileRemover(pth string) {
	if err := os.Remove(pth); err != nil {
		const msg = "Error removing file at: %q\n    ERROR: %s"
		log.Printf(msg, pth, err.Error())
	}
}
func loggingCloser(c io.Closer, pth string) {
	if err := c.Close(); err != nil {
		if pth == "" {
			const msg = "Error closing item\n    ERROR: %s"
			log.Printf(msg, err.Error())
		} else {
			const msg = "Error closing file at: %q\n    ERROR: %s"
			log.Printf(msg, pth, err.Error())
		}
	}
}

func strToBytes(s string) []byte {
	return *(*[]byte)(unsafe.Pointer(
		&reflect.SliceHeader{
			Data: (*reflect.StringHeader)(unsafe.Pointer(&s)).Data,
			Len:  len(s),
			Cap:  len(s),
		}),
	)
}

func bytesToStr(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}
