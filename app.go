package xgservice

import (
	_ "expvar"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/pprof"
	"runtime"
	"strconv"
	"time"

	"github.com/NYTimes/gziphandler"
	"github.com/gocql/gocql"
	"github.com/julienschmidt/httprouter"
)

var buildID []byte
var httpPort *int
var httpStaticPort *int
var buildNumber *string

var emptyState map[string]interface{}

var gitRepoURI *string
var gitRepoUsername *string
var gitRepoPassword *string

var session *gocql.Session

func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
}

func setupResponse(w *http.ResponseWriter, req *http.Request) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, PATCH")
	(*w).Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, Cache-Control")
}

type corsRouter struct {
	router *httprouter.Router
}

func (cr *corsRouter) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	log.Println("Method ", ((*req).Method))
	if (*req).Method == "OPTIONS" {
		setupResponse(&w, req)
		w.WriteHeader(http.StatusOK)
		return
	}
	enableCors(&w)
	cr.router.ServeHTTP(w, req)
}

func runServer() {
	log.Println("Starting HTTP server")

	router := httprouter.New()
	router.GET("/health", getHealth)

	router.POST("/auth/create", createAuth)
	router.GET("/auth/check", checkAuth)

	router.POST("/repo/files/*filename", uploadFilesMultipart)
	router.PUT("/repo/files/*filename", uploadFile)
	router.DELETE("/repo/files/*filename", removeFile)
	router.GET("/repo/files/*filename", downloadFile)

	router.HandlerFunc(http.MethodGet, "/debug/pprof/", pprof.Index)
	router.HandlerFunc(http.MethodGet, "/debug/pprof/cmdline", pprof.Cmdline)
	router.HandlerFunc(http.MethodGet, "/debug/pprof/profile", pprof.Profile)
	router.HandlerFunc(http.MethodGet, "/debug/pprof/symbol", pprof.Symbol)
	router.HandlerFunc(http.MethodGet, "/debug/pprof/trace", pprof.Trace)
	router.Handler(http.MethodGet, "/debug/pprof/goroutine", pprof.Handler("goroutine"))
	router.Handler(http.MethodGet, "/debug/pprof/heap", pprof.Handler("heap"))
	router.Handler(http.MethodGet, "/debug/pprof/threadcreate", pprof.Handler("threadcreate"))
	router.Handler(http.MethodGet, "/debug/pprof/block", pprof.Handler("block"))

	log.Printf("Listening on port %d \r\n", *httpPort)
	handler := corsRouter{router: router}
	hgz := gziphandler.GzipHandler(&handler)
	s := &http.Server{
		Addr:           ":" + strconv.Itoa(*httpPort),
		Handler:        hgz,
		ReadTimeout:    300 * time.Second,
		WriteTimeout:   300 * time.Second,
		IdleTimeout:    300 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	s.SetKeepAlivesEnabled(true)
	log.Fatal(s.ListenAndServe())
}

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}

// PrintMemUsage outputs the current, total and OS memory being used. As well as the number
// of garage collection cycles completed.
func PrintMemUsage() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	// For info on each, see: https://golang.org/pkg/runtime/#MemStats
	fmt.Printf("Alloc = %v MiB", bToMb(m.Alloc))
	fmt.Printf("\tTotalAlloc = %v MiB", bToMb(m.TotalAlloc))
	fmt.Printf("\tSys = %v MiB", bToMb(m.Sys))
	fmt.Printf("\tNumGC = %v\n", m.NumGC)
}

func runStaticServer() {
	fs := FileServerReact(http.Dir(*staticPath))
	http.Handle("/", fs)

	log.Println("Listening...")
	http.ListenAndServe(":"+strconv.Itoa(*httpStaticPort), nil)
}

func main() {
	PrintMemUsage()
	emptyState = make(map[string]interface{})
	httpPort = flag.Int("port", 8888, "server's HTTP port")
	strBuildID := string(buildID)
	buildNumber = flag.String("build", strBuildID, "build number for the health endpoint")
	repoPath = flag.String("repoPath", "/var/lib/xg-service/repo", "The path of the repository")
	cClusterHosts := flag.String("cClusterHosts", "localhost", "a cassandra cluster's host name")
	// cKeySpace := flag.String("cKeyspace", "testing", "a cassandra cluster's keyspace")
	cPort := flag.Int("cPort", 9042, "a Cassandra cluster's port")

	rand.Read(jwtSecret)

	flag.Parse()
	// go runStaticServer()
	cluster := gocql.NewCluster(*cClusterHosts)
	// cluster.Keyspace = *cKeySpace
	cluster.Consistency = gocql.Quorum
	cluster.Port = *cPort
	cluster.Timeout = 30000 * time.Millisecond
	session, _ = cluster.CreateSession()
	defer session.Close()
	errInitDb := initDb()
	if errInitDb != nil {
		log.Println(errInitDb)
		return
	}

	runServer()
}

func applyScript(always bool, script string) (err error) {
	if !always {
		if cntRows := session.Query(`SELECT * FROM xgdb.dbpatches WHERE name=?`, script).Iter().NumRows(); cntRows > 0 {
			log.Println("Ignoring script " + script)
			return nil
		}
	}

	b, err := ioutil.ReadFile("./database/" + script + ".cql")
	if err != nil {
		log.Println(err)
		return err
	}
	commands := strings.Split(string(b), ";")
	for _, command := range commands {
		if len(strings.Trim(command, " \t\r\n")) > 0 {
			if err := session.Query(command + ";").Exec(); err != nil {
				log.Fatal(err, command)
				return err
			}
		}
	}
	return nil
}

func initDb() (err error) {
	log.Println("Database initialization started")
	if err := applyScript(true, "init"); err != nil {
		log.Println(err)
		return err
	}

	log.Println("Database initialization finished")
	return nil
}
