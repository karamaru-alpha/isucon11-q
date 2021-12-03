package main

import (
	"bytes"
	"crypto/ecdsa"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	goLog "log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-sql-driver/mysql"
	"github.com/goccy/go-json"
	"github.com/gorilla/sessions"
	"github.com/jmoiron/sqlx"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/labstack/gommon/log"
)

const (
	sessionName                 = "isucondition_go"
	conditionLimit              = 20
	frontendContentsPath        = "../public"
	jiaJWTSigningKeyPath        = "../ec256-public.pem"
	defaultIconFilePath         = "../NoImage.jpg"
	iconFilePath                = "../icons"
	defaultJIAServiceURL        = "http://localhost:5000"
	mysqlErrNumDuplicateEntry   = 1062
	conditionLevelInfo          = "info"
	conditionLevelWarning       = "warning"
	conditionLevelCritical      = "critical"
	scoreConditionLevelInfo     = 3
	scoreConditionLevelWarning  = 2
	scoreConditionLevelCritical = 1
	jiaServiceUrl               = "http://127.0.0.1:4999"
)

var (
	db                  *sqlx.DB
	sessionStore        sessions.Store
	mySQLConnectionData *MySQLConnectionEnv

	jiaJWTSigningKey *ecdsa.PublicKey

	postIsuConditionTargetBaseURL string // JIAへのactivate時に登録する，ISUがconditionを送る先のURL
)

type JSONSerializer struct{}

func (j *JSONSerializer) Serialize(c echo.Context, i interface{}, indent string) error {
	enc := json.NewEncoder(c.Response())
	return enc.Encode(i)
}

func (j *JSONSerializer) Deserialize(c echo.Context, i interface{}) error {
	err := json.NewDecoder(c.Request().Body).Decode(i)
	if ute, ok := err.(*json.UnmarshalTypeError); ok {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Unmarshal type error: expected=%v, got=%v, field=%v, offset=%v", ute.Type, ute.Value, ute.Field, ute.Offset)).SetInternal(err)
	} else if se, ok := err.(*json.SyntaxError); ok {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Syntax error: offset=%v, error=%v", se.Offset, se.Error())).SetInternal(err)
	}
	return err
}

type Config struct {
	Name string `db:"name"`
	URL  string `db:"url"`
}

type Isu struct {
	ID         int       `db:"id" json:"id"`
	JIAIsuUUID string    `db:"jia_isu_uuid" json:"jia_isu_uuid"`
	Name       string    `db:"name" json:"name"`
	Image      []byte    `db:"image" json:"-"`
	Character  string    `db:"character" json:"character"`
	JIAUserID  string    `db:"jia_user_id" json:"-"`
	CreatedAt  time.Time `db:"created_at" json:"-"`
	UpdatedAt  time.Time `db:"updated_at" json:"-"`
}

type IsuFromJIA struct {
	Character string `json:"character"`
}

type GetIsuListResponse struct {
	ID                 int                      `json:"id"`
	JIAIsuUUID         string                   `json:"jia_isu_uuid"`
	Name               string                   `json:"name"`
	Character          string                   `json:"character"`
	LatestIsuCondition *GetIsuConditionResponse `json:"latest_isu_condition"`
}

type IsuCondition struct {
	ID         int       `db:"id"`
	JIAIsuUUID string    `db:"jia_isu_uuid"`
	Timestamp  time.Time `db:"timestamp"`
	IsSitting  bool      `db:"is_sitting"`
	Condition  string    `db:"condition"`
	Level      string    `db:"level"`
	Message    string    `db:"message"`
	// CreatedAt  time.Time `db:"created_at"`
}

type MySQLConnectionEnv struct {
	Host     string
	Port     string
	User     string
	DBName   string
	Password string
}

type InitializeRequest struct {
	JIAServiceURL string `json:"jia_service_url"`
}

type InitializeResponse struct {
	Language string `json:"language"`
}

type GetMeResponse struct {
	JIAUserID string `json:"jia_user_id"`
}

type GraphResponse struct {
	StartAt             int64           `json:"start_at"`
	EndAt               int64           `json:"end_at"`
	Data                *GraphDataPoint `json:"data"`
	ConditionTimestamps []int64         `json:"condition_timestamps"`
}

type GraphDataPoint struct {
	Score      int                  `json:"score"`
	Percentage ConditionsPercentage `json:"percentage"`
}

type ConditionsPercentage struct {
	Sitting      int `json:"sitting"`
	IsBroken     int `json:"is_broken"`
	IsDirty      int `json:"is_dirty"`
	IsOverweight int `json:"is_overweight"`
}

type GraphDataPointWithInfo struct {
	JIAIsuUUID          string
	StartAt             time.Time
	Data                GraphDataPoint
	ConditionTimestamps []int64
}

type GetIsuConditionResponse struct {
	JIAIsuUUID     string `json:"jia_isu_uuid"`
	IsuName        string `json:"isu_name"`
	Timestamp      int64  `json:"timestamp"`
	IsSitting      bool   `json:"is_sitting"`
	Condition      string `json:"condition"`
	ConditionLevel string `json:"condition_level"`
	Message        string `json:"message"`
}

type TrendResponse struct {
	Character string            `json:"character"`
	Info      []*TrendCondition `json:"info"`
	Warning   []*TrendCondition `json:"warning"`
	Critical  []*TrendCondition `json:"critical"`
}

type TrendCondition struct {
	ID        int   `json:"isu_id"`
	Timestamp int64 `json:"timestamp"`
}

type PostIsuConditionRequest struct {
	IsSitting bool   `json:"is_sitting"`
	Condition string `json:"condition"`
	Message   string `json:"message"`
	Timestamp int64  `json:"timestamp"`
}

type JIAServiceRequest struct {
	TargetBaseURL string `json:"target_base_url"`
	IsuUUID       string `json:"isu_uuid"`
}

// onMemory
type omIsuListT struct {
	M sync.RWMutex
	V map[string][]Isu //jia_user_id
}

var omIsuList omIsuListT

func (o *omIsuListT) Get(k string) ([]Isu, bool) {
	o.M.RLock()
	defer o.M.RUnlock()

	v, ok := o.V[k]
	return v, ok
}

func (o *omIsuListT) Set(i []Isu) {
	o.M.Lock()
	for _, v := range i {
		o.V[v.JIAUserID] = append(o.V[v.JIAUserID], v)
	}
	o.M.Unlock()
}

type omIsuExistT struct {
	M sync.RWMutex
	V map[string]interface{} //jia_isu_uuid
}

var omIsuExist omIsuExistT

func (o *omIsuExistT) Exist(k string) bool {
	o.M.RLock()
	defer o.M.RUnlock()
	_, ok := o.V[k]
	return ok
}

func (o *omIsuExistT) Set(i []Isu) {
	o.M.Lock()
	for _, v := range i {
		o.V[v.JIAIsuUUID] = struct{}{}
	}
	o.M.Unlock()
}

type omIsuNamesT struct {
	M sync.RWMutex
	V map[string]string
}

var omIsuNames omIsuNamesT

type omIsuConditionPostsT struct {
	M sync.RWMutex
	V []IsuCondition
}

var omIsuConditionPosts omIsuConditionPostsT

func (o *omIsuConditionPostsT) Get() []IsuCondition {
	o.M.RLock()
	defer o.M.RUnlock()
	isuConList := o.V
	o.V = []IsuCondition{}
	return isuConList
}

func (o *omIsuConditionPostsT) Set(v []IsuCondition) {
	o.M.Lock()
	o.V = append(o.V, v...)
	o.M.Unlock()
}

type omTrendResT struct {
	M sync.RWMutex
	T time.Time
	V []TrendResponse
}

var omTrendRes omTrendResT

func (o *omTrendResT) Get() ([]TrendResponse, bool) {
	o.M.RLock()
	defer o.M.RUnlock()
	if o.T.After(time.Now()) {
		return o.V, true
	}
	return nil, false
}

func (o *omTrendResT) SetExpire() {
	o.M.Lock()
	o.T = time.Now().Add(time.Hour)
	o.M.Unlock()
}

func (o *omTrendResT) Set(v []TrendResponse) {
	o.M.Lock()
	o.T = time.Now().Add(time.Hour)
	o.V = v
	o.M.Unlock()
}

func getEnv(key string, defaultValue string) string {
	val := os.Getenv(key)
	if val != "" {
		return val
	}
	return defaultValue
}

func NewMySQLConnectionEnv() *MySQLConnectionEnv {
	return &MySQLConnectionEnv{
		Host:     getEnv("MYSQL_HOST", "127.0.0.1"),
		Port:     getEnv("MYSQL_PORT", "3306"),
		User:     getEnv("MYSQL_USER", "isucon"),
		DBName:   getEnv("MYSQL_DBNAME", "isucondition"),
		Password: getEnv("MYSQL_PASS", "isucon"),
	}
}

func (mc *MySQLConnectionEnv) ConnectDB() (*sqlx.DB, error) {
	dsn := fmt.Sprintf("%v:%v@tcp(%v:%v)/%v?parseTime=true&loc=Asia%%2FTokyo&interpolateParams=true", mc.User, mc.Password, mc.Host, mc.Port, mc.DBName)
	return sqlx.Open("mysql", dsn)
}

func init() {
	sessionStore = sessions.NewCookieStore([]byte(getEnv("SESSION_KEY", "isucondition")))

	key, err := ioutil.ReadFile(jiaJWTSigningKeyPath)
	if err != nil {
		log.Fatalf("failed to read file: %v", err)
	}
	jiaJWTSigningKey, err = jwt.ParseECPublicKeyFromPEM(key)
	if err != nil {
		log.Fatalf("failed to parse ECDSA public key: %v", err)
	}
}

func main() {
	var err error

	// TODO
	logfile, err := os.OpenFile("/var/log/go.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		panic("cannnot open go.log:" + err.Error())
	}
	defer logfile.Close()
	goLog.SetOutput(io.MultiWriter(logfile, os.Stdout))

	e := echo.New()
	e.JSONSerializer = &JSONSerializer{}
	e.Use(middleware.Recover())

	e.POST("/initialize", postInitialize)

	e.POST("/api/auth", postAuthentication)
	e.POST("/api/signout", postSignout)
	e.GET("/api/user/me", getMe)
	e.GET("/api/isu", getIsuList)
	e.POST("/api/isu", postIsu)
	e.GET("/api/isu/:jia_isu_uuid", getIsuID)
	e.GET("/api/isu/:jia_isu_uuid/icon", getIsuIcon)
	e.GET("/api/isu/:jia_isu_uuid/graph", getIsuGraph)
	e.GET("/api/condition/:jia_isu_uuid", getIsuConditions)
	e.GET("/api/trend", getTrend)

	e.POST("/api/condition/:jia_isu_uuid", postIsuCondition)

	e.GET("/", getIndex)
	e.GET("/isu/:jia_isu_uuid", getIndex)
	e.GET("/isu/:jia_isu_uuid/condition", getIndex)
	e.GET("/isu/:jia_isu_uuid/graph", getIndex)
	e.GET("/register", getIndex)
	e.Static("/assets", frontendContentsPath+"/assets")

	mySQLConnectionData = NewMySQLConnectionEnv()

	db, err = mySQLConnectionData.ConnectDB()
	if err != nil {
		e.Logger.Fatalf("failed to connect db: %v", err)
		return
	}
	db.SetMaxOpenConns(1024)
	db.SetMaxIdleConns(1024)
	defer db.Close()

	postIsuConditionTargetBaseURL = os.Getenv("POST_ISUCONDITION_TARGET_BASE_URL")
	if postIsuConditionTargetBaseURL == "" {
		e.Logger.Fatalf("missing: POST_ISUCONDITION_TARGET_BASE_URL")
		return
	}

	socketFile := "/tmp/go.sock"
	os.Remove(socketFile)

	l, err := net.Listen("unix", socketFile)
	if err != nil {
		e.Logger.Fatal(err)
	}

	err = os.Chmod(socketFile, 0777)
	if err != nil {
		e.Logger.Fatal(err)
	}

	e.Listener = l

	serverPort := fmt.Sprintf(":%v", getEnv("SERVER_APP_PORT", "3000"))
	e.Logger.Fatal(e.Start(serverPort))
}

func getSession(r *http.Request) (*sessions.Session, error) {
	session, err := sessionStore.Get(r, sessionName)
	if err != nil {
		return nil, err
	}
	return session, nil
}

func getUserIDFromSession(c echo.Context) (string, int, error) {
	session, err := getSession(c.Request())
	if err != nil {
		return "", http.StatusInternalServerError, fmt.Errorf("failed to get session: %v", err)
	}
	_jiaUserID, ok := session.Values["jia_user_id"]
	if !ok {
		return "", http.StatusUnauthorized, fmt.Errorf("no session")
	}

	jiaUserID := _jiaUserID.(string)
	// var count int

	// err = db.Get(&count, "SELECT COUNT(*) FROM `user` WHERE `jia_user_id` = ?",
	// 	jiaUserID)
	// if err != nil {
	// 	return "", http.StatusInternalServerError, fmt.Errorf("db error: %v", err)
	// }

	// if count == 0 {
	// 	return "", http.StatusUnauthorized, fmt.Errorf("not found: user")
	// }

	return jiaUserID, 0, nil
}

// * POST /initialize
// サービスを初期化
func postInitialize(c echo.Context) error {

	omIsuList = omIsuListT{
		V: make(map[string][]Isu, 100),
	}
	omIsuExist = omIsuExistT{
		V: make(map[string]interface{}, 100),
	}
	omTrendRes = omTrendResT{
		T: time.Now().Add(-time.Minute),
	}
	omIsuNames = omIsuNamesT{
		V: make(map[string]string, 100),
	}
	omIsuConditionPosts = omIsuConditionPostsT{}

	var request InitializeRequest
	err := c.Bind(&request)
	if err != nil {
		return c.String(http.StatusBadRequest, "bad request body")
	}

	cmd := exec.Command("../sql/init.sh")
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stderr
	err = cmd.Run()
	if err != nil {
		goLog.Printf("exec init.sh error: %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	// 	ID         int       `db:"id" json:"id"`
	// JIAIsuUUID string    `db:"jia_isu_uuid" json:"jia_isu_uuid"`
	// Name       string    `db:"name" json:"name"`
	// Image      []byte    `db:"image" json:"-"`
	// Character  string    `db:"character" json:"character"`
	// JIAUserID  string    `db:"jia_user_id" json:"-"`
	// CreatedAt  time.Time `db:"created_at" json:"-"`
	// UpdatedAt  time.Time `db:"updated_at" json:"-"`

	var isuImages []Isu
	err = db.Select(&isuImages, `SELECT jia_isu_uuid, jia_user_id, image FROM isu`)
	if err != nil {
		return c.NoContent(http.StatusInternalServerError)
	}
	if err = os.RemoveAll(iconFilePath); err != nil {
		return c.NoContent(http.StatusInternalServerError)
	}
	if err := os.MkdirAll(iconFilePath, os.ModePerm); err != nil {
		return c.NoContent(http.StatusInternalServerError)
	}

	for _, v := range isuImages {
		if err := os.WriteFile(fmt.Sprintf("%s/%s_%s", iconFilePath, v.JIAUserID, v.JIAIsuUUID), v.Image, os.ModePerm); err != nil {
			c.Logger().Error(err)
			return c.NoContent(http.StatusInternalServerError)
		}
	}

	var isuList []Isu
	err = db.Select(&isuList, `SELECT * FROM isu`)
	if err != nil {
		return c.NoContent(http.StatusInternalServerError)
	}

	omIsuList.Set(isuList)
	omIsuExist.Set(isuList)

	omIsuNames.M.Lock()
	for _, v := range isuList {
		omIsuNames.V[v.JIAIsuUUID+v.JIAUserID] = v.Name
	}
	omIsuNames.M.Unlock()

	go postIsuConditionLoop()

	initTrend()

	if _, err = db.Exec(`ALTER TABLE isu DROP COLUMN image`); err != nil {
		return c.NoContent(http.StatusInternalServerError)
	}
	return c.JSON(http.StatusOK, InitializeResponse{
		Language: "go",
	})
}

// * POST /api/auth
// サインアップ・サインイン
func postAuthentication(c echo.Context) error {
	reqJwt := strings.TrimPrefix(c.Request().Header.Get("Authorization"), "Bearer ")

	token, err := jwt.Parse(reqJwt, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, jwt.NewValidationError(fmt.Sprintf("unexpected signing method: %v", token.Header["alg"]), jwt.ValidationErrorSignatureInvalid)
		}
		return jiaJWTSigningKey, nil
	})
	if err != nil {
		switch err.(type) {
		case *jwt.ValidationError:
			return c.String(http.StatusForbidden, "forbidden")
		default:
			goLog.Print(err)
			return c.NoContent(http.StatusInternalServerError)
		}
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		goLog.Printf("invalid JWT payload")
		return c.NoContent(http.StatusInternalServerError)
	}
	jiaUserIDVar, ok := claims["jia_user_id"]
	if !ok {
		return c.String(http.StatusBadRequest, "invalid JWT payload")
	}
	jiaUserID, ok := jiaUserIDVar.(string)
	if !ok {
		return c.String(http.StatusBadRequest, "invalid JWT payload")
	}

	_, err = db.Exec("INSERT IGNORE INTO user (`jia_user_id`) VALUES (?)", jiaUserID)
	if err != nil {
		goLog.Printf("db error: %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	session, err := getSession(c.Request())
	if err != nil {
		goLog.Print(err)
		return c.NoContent(http.StatusInternalServerError)
	}

	session.Values["jia_user_id"] = jiaUserID
	err = session.Save(c.Request(), c.Response())
	if err != nil {
		goLog.Print(err)
		return c.NoContent(http.StatusInternalServerError)
	}

	return c.NoContent(http.StatusOK)
}

// * POST /api/signout
// サインアウト
func postSignout(c echo.Context) error {
	_, errStatusCode, err := getUserIDFromSession(c)
	if err != nil {
		if errStatusCode == http.StatusUnauthorized {
			return c.String(http.StatusUnauthorized, "you are not signed in")
		}

		goLog.Print(err)
		return c.NoContent(http.StatusInternalServerError)
	}

	session, err := getSession(c.Request())
	if err != nil {
		goLog.Print(err)
		return c.NoContent(http.StatusInternalServerError)
	}

	session.Options = &sessions.Options{MaxAge: -1, Path: "/"}
	err = session.Save(c.Request(), c.Response())
	if err != nil {
		goLog.Print(err)
		return c.NoContent(http.StatusInternalServerError)
	}

	return c.NoContent(http.StatusOK)
}

// * GET /api/user/me
// サインインしている自分自身の情報を取得
func getMe(c echo.Context) error {
	jiaUserID, errStatusCode, err := getUserIDFromSession(c)
	if err != nil {
		if errStatusCode == http.StatusUnauthorized {
			return c.String(http.StatusUnauthorized, "you are not signed in")
		}

		goLog.Print(err)
		return c.NoContent(http.StatusInternalServerError)
	}

	res := GetMeResponse{JIAUserID: jiaUserID}
	return c.JSON(http.StatusOK, res)
}

// * GET /api/isu
// ISUの一覧を取得
// ? POST /api/condition/:jia_isu_uuid で受け取ったコンディションの反映が遅れることをベンチマーカーは許容
func getIsuList(c echo.Context) error {
	jiaUserID, errStatusCode, err := getUserIDFromSession(c)
	if err != nil {
		if errStatusCode == http.StatusUnauthorized {
			return c.String(http.StatusUnauthorized, "you are not signed in")
		}

		goLog.Print(err)
		return c.NoContent(http.StatusInternalServerError)
	}
	responseList := []GetIsuListResponse{}

	isuList, ok := omIsuList.Get(jiaUserID)
	if !ok {
		goLog.Print("no")
		return c.JSON(http.StatusOK, responseList)
	}
	sort.Slice(isuList, func(i, j int) bool {
		return isuList[i].ID > isuList[j].ID
	})

	for _, isu := range isuList {
		var lastCondition IsuCondition
		foundLastCondition := true
		err = db.Get(&lastCondition, "SELECT * FROM `isu_condition` WHERE `jia_isu_uuid` = ? ORDER BY `timestamp` DESC LIMIT 1",
			isu.JIAIsuUUID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				foundLastCondition = false
			} else {
				goLog.Printf("db error: %v", err)
				return c.NoContent(http.StatusInternalServerError)
			}
		}

		var formattedCondition *GetIsuConditionResponse
		if foundLastCondition {
			formattedCondition = &GetIsuConditionResponse{
				JIAIsuUUID:     lastCondition.JIAIsuUUID,
				IsuName:        isu.Name,
				Timestamp:      lastCondition.Timestamp.Unix(),
				IsSitting:      lastCondition.IsSitting,
				Condition:      lastCondition.Condition,
				ConditionLevel: lastCondition.Level,
				Message:        lastCondition.Message,
			}
		}

		res := GetIsuListResponse{
			ID:                 isu.ID,
			JIAIsuUUID:         isu.JIAIsuUUID,
			Name:               isu.Name,
			Character:          isu.Character,
			LatestIsuCondition: formattedCondition}
		responseList = append(responseList, res)
	}

	return c.JSON(http.StatusOK, responseList)
}

// * POST /api/isu
// ISUを登録
func postIsu(c echo.Context) error {
	jiaUserID, errStatusCode, err := getUserIDFromSession(c)
	if err != nil {
		if errStatusCode == http.StatusUnauthorized {
			return c.String(http.StatusUnauthorized, "you are not signed in")
		}

		goLog.Print(err)
		return c.NoContent(http.StatusInternalServerError)
	}

	useDefaultImage := false

	jiaIsuUUID := c.FormValue("jia_isu_uuid")
	isuName := c.FormValue("isu_name")
	fh, err := c.FormFile("image")
	if err != nil {
		if !errors.Is(err, http.ErrMissingFile) {
			return c.String(http.StatusBadRequest, "bad format: icon")
		}
		useDefaultImage = true
	}
	if useDefaultImage {
		file, err := os.Open(defaultIconFilePath)
		if err != nil {
			goLog.Print(err)
			return c.NoContent(http.StatusInternalServerError)
		}
		defer file.Close()

		f, err := os.Create(fmt.Sprintf("%s/%s_%s", iconFilePath, jiaUserID, jiaIsuUUID))
		if err != nil {
			goLog.Print(err)
			return c.NoContent(http.StatusInternalServerError)
		}
		defer f.Close()

		_, err = io.Copy(f, file)
		if err != nil {
			return c.NoContent(http.StatusInternalServerError)
		}
	} else {
		file, err := fh.Open()
		if err != nil {
			goLog.Print(err)
			return c.NoContent(http.StatusInternalServerError)
		}
		defer file.Close()

		f, err := os.Create(fmt.Sprintf("%s/%s_%s", iconFilePath, jiaUserID, jiaIsuUUID))
		if err != nil {
			goLog.Print(err)
			return c.NoContent(http.StatusInternalServerError)
		}
		defer f.Close()

		_, err = io.Copy(f, file)
		if err != nil {
			return c.NoContent(http.StatusInternalServerError)
		}
	}

	tx, err := db.Beginx()
	if err != nil {
		goLog.Printf("db error: %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	defer tx.Rollback()

	_, err = tx.Exec("INSERT INTO `isu`"+
		"	(`jia_isu_uuid`, `name`, `jia_user_id`) VALUES (?, ?, ?)",
		jiaIsuUUID, isuName, jiaUserID)
	if err != nil {
		mysqlErr, ok := err.(*mysql.MySQLError)

		if ok && mysqlErr.Number == uint16(mysqlErrNumDuplicateEntry) {
			return c.String(http.StatusConflict, "duplicated: isu")
		}

		goLog.Printf("db error: %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	targetURL := jiaServiceUrl + "/api/activate"
	body := JIAServiceRequest{postIsuConditionTargetBaseURL, jiaIsuUUID}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		goLog.Print(err)
		return c.NoContent(http.StatusInternalServerError)
	}

	reqJIA, err := http.NewRequest(http.MethodPost, targetURL, bytes.NewBuffer(bodyJSON))
	if err != nil {
		goLog.Print(err)
		return c.NoContent(http.StatusInternalServerError)
	}

	reqJIA.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(reqJIA)
	if err != nil {
		goLog.Printf("failed to request to JIAService: %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	defer res.Body.Close()

	resBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		goLog.Print(err)
		return c.NoContent(http.StatusInternalServerError)
	}

	if res.StatusCode != http.StatusAccepted {
		goLog.Printf("JIAService returned error: status code %v, message: %v", res.StatusCode, string(resBody))
		return c.String(res.StatusCode, "JIAService returned error")
	}

	var isuFromJIA IsuFromJIA
	err = json.Unmarshal(resBody, &isuFromJIA)
	if err != nil {
		goLog.Print(err)
		return c.NoContent(http.StatusInternalServerError)
	}

	_, err = tx.Exec("UPDATE `isu` SET `character` = ? WHERE `jia_isu_uuid` = ?", isuFromJIA.Character, jiaIsuUUID)
	if err != nil {
		goLog.Printf("db error: %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	var isu Isu
	err = tx.Get(
		&isu,
		"SELECT * FROM `isu` WHERE `jia_isu_uuid` = ? AND `jia_user_id` = ?",
		jiaIsuUUID, jiaUserID)
	if err != nil {
		goLog.Printf("db error: %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	err = tx.Commit()
	if err != nil {
		goLog.Printf("db error: %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	omIsuList.Set([]Isu{isu})
	omIsuExist.Set([]Isu{isu})

	omIsuNames.M.Lock()
	omIsuNames.V[jiaIsuUUID+jiaUserID] = isuName
	omIsuNames.M.Unlock()
	return c.JSON(http.StatusCreated, isu)
}

// * GET /api/isu/:jia_isu_uuid
// ISUの情報を取得
func getIsuID(c echo.Context) error {
	jiaUserID, errStatusCode, err := getUserIDFromSession(c)
	if err != nil {
		if errStatusCode == http.StatusUnauthorized {
			return c.String(http.StatusUnauthorized, "you are not signed in")
		}

		goLog.Print(err)
		return c.NoContent(http.StatusInternalServerError)
	}

	jiaIsuUUID := c.Param("jia_isu_uuid")

	isuList, _ := omIsuList.Get(jiaUserID)
	for _, v := range isuList {
		if v.JIAIsuUUID == jiaIsuUUID {
			return c.JSON(http.StatusOK, v)
		}
	}

	return c.String(http.StatusNotFound, "not found: isu")
}

// * GET /api/isu/:jia_isu_uuid/icon
// ISUのアイコンを取得
func getIsuIcon(c echo.Context) error {
	jiaUserID, errStatusCode, err := getUserIDFromSession(c)
	if err != nil {
		if errStatusCode == http.StatusUnauthorized {
			return c.String(http.StatusUnauthorized, "you are not signed in")
		}

		goLog.Print(err)
		return c.NoContent(http.StatusInternalServerError)
	}

	jiaIsuUUID := c.Param("jia_isu_uuid")

	if !omIsuExist.Exist(jiaIsuUUID) {
		return c.String(http.StatusNotFound, "not found: isu")
	}

	image, err := os.ReadFile(fmt.Sprintf("%s/%s_%s", iconFilePath, jiaUserID, jiaIsuUUID))
	if err != nil {
		return c.String(http.StatusNotFound, "not found: isu")
	}

	return c.Blob(http.StatusOK, "", image)
}

// * GET /api/isu/:jia_isu_uuid/graph
// ISUのコンディショングラフ描画のための情報を取得
// ? POST /api/condition/:jia_isu_uuid で受け取ったコンディションの反映が遅れることをベンチマーカーは許容(1s)
// ! GETでスコア獲得
func getIsuGraph(c echo.Context) error {
	jiaUserID, errStatusCode, err := getUserIDFromSession(c)
	if err != nil {
		if errStatusCode == http.StatusUnauthorized {
			return c.String(http.StatusUnauthorized, "you are not signed in")
		}

		goLog.Print(err)
		return c.NoContent(http.StatusInternalServerError)
	}

	jiaIsuUUID := c.Param("jia_isu_uuid")
	datetimeStr := c.QueryParam("datetime")
	if datetimeStr == "" {
		return c.String(http.StatusBadRequest, "missing: datetime")
	}
	datetimeInt64, err := strconv.ParseInt(datetimeStr, 10, 64)
	if err != nil {
		return c.String(http.StatusBadRequest, "bad format: datetime")
	}
	date := time.Unix(datetimeInt64, 0).Truncate(time.Hour)

	var isExists bool
	isuList, _ := omIsuList.Get(jiaUserID)
	for _, v := range isuList {
		if v.JIAIsuUUID == jiaIsuUUID {
			isExists = true
			break
		}
	}
	if !isExists {
		return c.String(http.StatusNotFound, "not found: isu")
	}

	res, err := generateIsuGraphResponse(jiaIsuUUID, date)
	if err != nil {
		goLog.Print(err)
		return c.NoContent(http.StatusInternalServerError)
	}

	if err != nil {
		goLog.Printf("db error: %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}

	return c.JSON(http.StatusOK, res)
}

// グラフのデータ点を一日分生成
func generateIsuGraphResponse(jiaIsuUUID string, graphDate time.Time) ([]GraphResponse, error) {
	dataPoints := []GraphDataPointWithInfo{}
	conditionsInThisHour := []IsuCondition{}
	timestampsInThisHour := []int64{}
	var startTimeInThisHour time.Time
	var condition IsuCondition
	rows, err := db.Queryx(`
		SELECT * FROM isu_condition WHERE jia_isu_uuid = ? AND ? <= timestamp AND timestamp < ? ORDER BY timestamp ASC
	`, jiaIsuUUID, graphDate, graphDate.Add(24*time.Hour))
	if err != nil {
		return nil, fmt.Errorf("db error: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		err = rows.StructScan(&condition)
		if err != nil {
			return nil, err
		}
		truncatedConditionTime := condition.Timestamp.Truncate(time.Hour)
		if truncatedConditionTime != startTimeInThisHour {
			if len(conditionsInThisHour) > 0 {
				data, err := calculateGraphDataPoint(conditionsInThisHour)
				if err != nil {
					return nil, err
				}

				dataPoints = append(dataPoints,
					GraphDataPointWithInfo{
						JIAIsuUUID:          jiaIsuUUID,
						StartAt:             startTimeInThisHour,
						Data:                data,
						ConditionTimestamps: timestampsInThisHour})
			}

			startTimeInThisHour = truncatedConditionTime
			conditionsInThisHour = []IsuCondition{}
			timestampsInThisHour = []int64{}
		}
		conditionsInThisHour = append(conditionsInThisHour, condition)
		timestampsInThisHour = append(timestampsInThisHour, condition.Timestamp.Unix())
	}

	if len(conditionsInThisHour) > 0 {
		data, err := calculateGraphDataPoint(conditionsInThisHour)
		if err != nil {
			return nil, err
		}

		dataPoints = append(dataPoints,
			GraphDataPointWithInfo{
				JIAIsuUUID:          jiaIsuUUID,
				StartAt:             startTimeInThisHour,
				Data:                data,
				ConditionTimestamps: timestampsInThisHour})
	}

	endTime := graphDate.Add(time.Hour * 24)
	startIndex := len(dataPoints)
	endNextIndex := len(dataPoints)
	for i, graph := range dataPoints {
		if startIndex == len(dataPoints) && !graph.StartAt.Before(graphDate) {
			startIndex = i
		}
		if endNextIndex == len(dataPoints) && graph.StartAt.After(endTime) {
			endNextIndex = i
		}
	}

	filteredDataPoints := []GraphDataPointWithInfo{}
	if startIndex < endNextIndex {
		filteredDataPoints = dataPoints[startIndex:endNextIndex]
	}

	responseList := []GraphResponse{}
	index := 0
	thisTime := graphDate

	for thisTime.Before(graphDate.Add(time.Hour * 24)) {
		var data *GraphDataPoint
		timestamps := []int64{}

		if index < len(filteredDataPoints) {
			dataWithInfo := filteredDataPoints[index]

			if dataWithInfo.StartAt.Equal(thisTime) {
				data = &dataWithInfo.Data
				timestamps = dataWithInfo.ConditionTimestamps
				index++
			}
		}

		resp := GraphResponse{
			StartAt:             thisTime.Unix(),
			EndAt:               thisTime.Add(time.Hour).Unix(),
			Data:                data,
			ConditionTimestamps: timestamps,
		}
		responseList = append(responseList, resp)

		thisTime = thisTime.Add(time.Hour)
	}

	return responseList, nil
}

// 複数のISUのコンディションからグラフの一つのデータ点を計算
func calculateGraphDataPoint(isuConditions []IsuCondition) (GraphDataPoint, error) {
	conditionsCount := map[string]int{"is_broken": 0, "is_dirty": 0, "is_overweight": 0}
	rawScore := 0
	for _, condition := range isuConditions {
		badConditionsCount := 0

		if !isValidConditionFormat(condition.Condition) {
			return GraphDataPoint{}, fmt.Errorf("invalid condition format")
		}

		for _, condStr := range strings.Split(condition.Condition, ",") {
			keyValue := strings.Split(condStr, "=")

			conditionName := keyValue[0]
			if keyValue[1] == "true" {
				conditionsCount[conditionName] += 1
				badConditionsCount++
			}
		}

		if badConditionsCount >= 3 {
			rawScore += scoreConditionLevelCritical
		} else if badConditionsCount >= 1 {
			rawScore += scoreConditionLevelWarning
		} else {
			rawScore += scoreConditionLevelInfo
		}
	}

	sittingCount := 0
	for _, condition := range isuConditions {
		if condition.IsSitting {
			sittingCount++
		}
	}

	isuConditionsLength := len(isuConditions)

	score := rawScore * 100 / 3 / isuConditionsLength

	sittingPercentage := sittingCount * 100 / isuConditionsLength
	isBrokenPercentage := conditionsCount["is_broken"] * 100 / isuConditionsLength
	isOverweightPercentage := conditionsCount["is_overweight"] * 100 / isuConditionsLength
	isDirtyPercentage := conditionsCount["is_dirty"] * 100 / isuConditionsLength

	dataPoint := GraphDataPoint{
		Score: score,
		Percentage: ConditionsPercentage{
			Sitting:      sittingPercentage,
			IsBroken:     isBrokenPercentage,
			IsOverweight: isOverweightPercentage,
			IsDirty:      isDirtyPercentage,
		},
	}
	return dataPoint, nil
}

// *GET /api/condition/:jia_isu_uuid
// ISUのコンディションを取得
// ? POST /api/condition/:jia_isu_uuid で受け取ったコンディションの反映が遅れることをベンチマーカーは許容(1s)
// ! 最新GETでスコア獲得
func getIsuConditions(c echo.Context) error {
	jiaUserID, errStatusCode, err := getUserIDFromSession(c)
	if err != nil {
		if errStatusCode == http.StatusUnauthorized {
			return c.String(http.StatusUnauthorized, "you are not signed in")
		}

		goLog.Print(err)
		return c.NoContent(http.StatusInternalServerError)
	}

	jiaIsuUUID := c.Param("jia_isu_uuid")
	if jiaIsuUUID == "" {
		return c.String(http.StatusBadRequest, "missing: jia_isu_uuid")
	}

	endTimeInt64, err := strconv.ParseInt(c.QueryParam("end_time"), 10, 64)
	if err != nil {
		return c.String(http.StatusBadRequest, "bad format: end_time")
	}
	endTime := time.Unix(endTimeInt64, 0)
	conditionLevelCSV := c.QueryParam("condition_level")
	if conditionLevelCSV == "" {
		return c.String(http.StatusBadRequest, "missing: condition_level")
	}
	conditionLevel := map[string]interface{}{}
	for _, level := range strings.Split(conditionLevelCSV, ",") {
		conditionLevel[level] = struct{}{}
	}

	startTimeStr := c.QueryParam("start_time")
	var startTime time.Time
	if startTimeStr != "" {
		startTimeInt64, err := strconv.ParseInt(startTimeStr, 10, 64)
		if err != nil {
			return c.String(http.StatusBadRequest, "bad format: start_time")
		}
		startTime = time.Unix(startTimeInt64, 0)
	}

	omIsuNames.M.RLock()
	isuName, ok := omIsuNames.V[jiaIsuUUID+jiaUserID]
	omIsuNames.M.RUnlock()
	if !ok {
		return c.String(http.StatusNotFound, "not found: isu")
	}

	conditionsResponse, err := getIsuConditionsFromDB(db, jiaIsuUUID, endTime, conditionLevel, startTime, conditionLimit, isuName)
	if err != nil {
		goLog.Printf("db error: %v", err)
		return c.NoContent(http.StatusInternalServerError)
	}
	return c.JSON(http.StatusOK, conditionsResponse)
}

// ISUのコンディションをDBから取得
func getIsuConditionsFromDB(db *sqlx.DB, jiaIsuUUID string, endTime time.Time, conditionLevel map[string]interface{}, startTime time.Time,
	limit int, isuName string) ([]*GetIsuConditionResponse, error) {

	var levels []string
	for k := range conditionLevel {
		levels = append(levels, k)
	}
	var inPlaceHolders string

	conditions := []IsuCondition{}
	var err error

	if startTime.IsZero() {
		args := make([]interface{}, 0, len(levels)+3)
		args = append(args, jiaIsuUUID, endTime)
		if len(levels) < 3 {
			for _, v := range levels {
				args = append(args, v)
			}
			inPlaceHolders = "AND level IN (?" + strings.Repeat(",?", len(levels)-1) + ")"
		}
		args = append(args, limit)
		err = db.Select(&conditions,
			`SELECT * FROM isu_condition WHERE jia_isu_uuid = ?	AND timestamp < ? `+inPlaceHolders+` ORDER BY timestamp DESC LIMIT ?`, args...,
		)
	} else {
		args := make([]interface{}, 0, len(levels)+4)
		args = append(args, jiaIsuUUID, endTime, startTime)
		if len(levels) < 3 {
			for _, v := range levels {
				args = append(args, v)
			}
			inPlaceHolders = "AND level IN (?" + strings.Repeat(",?", len(levels)-1) + ")"
		}
		args = append(args, limit)
		err = db.Select(&conditions,
			`SELECT * FROM isu_condition WHERE jia_isu_uuid = ? AND timestamp < ? AND ? <= timestamp `+inPlaceHolders+` ORDER BY timestamp DESC LIMIT ?`,
			args...,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("db error: %v", err)
	}

	conditionsResponse := []*GetIsuConditionResponse{}
	for _, c := range conditions {
		data := GetIsuConditionResponse{
			JIAIsuUUID:     c.JIAIsuUUID,
			IsuName:        isuName,
			Timestamp:      c.Timestamp.Unix(),
			IsSitting:      c.IsSitting,
			Condition:      c.Condition,
			ConditionLevel: c.Level,
			Message:        c.Message,
		}
		conditionsResponse = append(conditionsResponse, &data)
	}

	return conditionsResponse, nil
}

// ISUのコンディションの文字列からコンディションレベルを計算
func calculateConditionLevel(condition string) (string, error) {
	var conditionLevel string

	warnCount := strings.Count(condition, "=true")
	switch warnCount {
	case 0:
		conditionLevel = conditionLevelInfo
	case 1, 2:
		conditionLevel = conditionLevelWarning
	case 3:
		conditionLevel = conditionLevelCritical
	default:
		return "", fmt.Errorf("unexpected warn count")
	}

	return conditionLevel, nil
}

// * GET /api/trend
// ISUの性格毎の最新のコンディション情報
// ? POST /api/condition/:jia_isu_uuid で受け取ったコンディションの反映が遅れることをベンチマーカーは許容
func getTrend(c echo.Context) error {

	if v, found := omTrendRes.Get(); found {
		return c.JSON(http.StatusOK, v)
	}

	omTrendRes.SetExpire()

	characterList := []string{
		"いじっぱり", "うっかりや", "おくびょう", "おだやか", "おっとり", "おとなしい", "がんばりや", "きまぐれ",
		"さみしがり", "しんちょう", "すなお", "ずぶとい", "せっかち", "てれや", "なまいき", "のうてんき",
		"のんき", "ひかえめ", "まじめ", "むじゃき", "やんちゃ", "ゆうかん", "ようき", "れいせい", "わんぱく",
	}

	res := []TrendResponse{}

	for _, character := range characterList {
		isuList := []Isu{}
		err := db.Select(&isuList,
			"SELECT * FROM `isu` WHERE `character` = ?",
			character,
		)
		if err != nil {
			goLog.Printf("db error: %v", err)
			return c.NoContent(http.StatusInternalServerError)
		}

		characterInfoIsuConditions := []*TrendCondition{}
		characterWarningIsuConditions := []*TrendCondition{}
		characterCriticalIsuConditions := []*TrendCondition{}
		for _, isu := range isuList {
			conditions := []IsuCondition{}
			err = db.Select(&conditions,
				"SELECT * FROM `isu_condition` WHERE `jia_isu_uuid` = ? ORDER BY timestamp DESC LIMIT 1",
				isu.JIAIsuUUID,
			)
			if err != nil {
				goLog.Printf("db error: %v", err)
				return c.NoContent(http.StatusInternalServerError)
			}

			if len(conditions) > 0 {
				isuLastCondition := conditions[0]
				trendCondition := TrendCondition{
					ID:        isu.ID,
					Timestamp: isuLastCondition.Timestamp.Unix(),
				}
				switch isuLastCondition.Level {
				case "info":
					characterInfoIsuConditions = append(characterInfoIsuConditions, &trendCondition)
				case "warning":
					characterWarningIsuConditions = append(characterWarningIsuConditions, &trendCondition)
				case "critical":
					characterCriticalIsuConditions = append(characterCriticalIsuConditions, &trendCondition)
				}
			}

		}

		sort.Slice(characterInfoIsuConditions, func(i, j int) bool {
			return characterInfoIsuConditions[i].Timestamp > characterInfoIsuConditions[j].Timestamp
		})
		sort.Slice(characterWarningIsuConditions, func(i, j int) bool {
			return characterWarningIsuConditions[i].Timestamp > characterWarningIsuConditions[j].Timestamp
		})
		sort.Slice(characterCriticalIsuConditions, func(i, j int) bool {
			return characterCriticalIsuConditions[i].Timestamp > characterCriticalIsuConditions[j].Timestamp
		})
		res = append(res,
			TrendResponse{
				Character: character,
				Info:      characterInfoIsuConditions,
				Warning:   characterWarningIsuConditions,
				Critical:  characterCriticalIsuConditions,
			})
	}

	omTrendRes.Set(res)

	return c.JSON(http.StatusOK, res)
}

func postIsuConditionLoop() {
	for range time.Tick(time.Millisecond * 250) {
		isuConList := omIsuConditionPosts.Get()
		if len(isuConList) == 0 {
			continue
		}

		args := make([]interface{}, 0, len(isuConList)*6)
		placeHolders := &strings.Builder{}
		for i, v := range isuConList {
			args = append(args, []interface{}{v.JIAIsuUUID, v.Timestamp, v.IsSitting, v.Condition, v.Message, v.Level}...)
			if i == 0 {
				placeHolders.WriteString(" (?, ?, ?, ?, ?, ?)")
			} else {
				placeHolders.WriteString(",(?, ?, ?, ?, ?, ?)")
			}
		}
		_, err := db.Exec(
			"INSERT INTO `isu_condition`"+
				"	(`jia_isu_uuid`, `timestamp`, `is_sitting`, `condition`, `message`, `level`)"+
				"	VALUES"+placeHolders.String(),
			args...)
		if err != nil {
			goLog.Println(err.Error())
		}
	}
}

// * POST /api/condition/:jia_isu_uuid
// ISUからのコンディションを受け取る
func postIsuCondition(c echo.Context) error {
	jiaIsuUUID := c.Param("jia_isu_uuid")
	if jiaIsuUUID == "" {
		return c.String(http.StatusBadRequest, "missing: jia_isu_uuid")
	}

	req := []PostIsuConditionRequest{}
	err := c.Bind(&req)
	if err != nil {
		return c.String(http.StatusBadRequest, "bad request body")
	} else if len(req) == 0 {
		return c.String(http.StatusBadRequest, "bad request body")
	}

	if !omIsuExist.Exist(jiaIsuUUID) {
		return c.String(http.StatusNotFound, "not found: isu")
	}

	var isuConList []IsuCondition

	for _, v := range req {
		if !isValidConditionFormat(v.Condition) {
			return c.String(http.StatusBadRequest, "bad request body")
		}
		level, err := calculateConditionLevel(v.Condition)
		if err != nil {
			return c.String(http.StatusBadRequest, "bad request body")
		}
		isuConList = append(isuConList, IsuCondition{
			JIAIsuUUID: jiaIsuUUID,
			Timestamp:  time.Unix(v.Timestamp, 0),
			IsSitting:  v.IsSitting,
			Condition:  v.Condition,
			Message:    v.Message,
			Level:      level,
		})
	}

	omIsuConditionPosts.Set(isuConList)

	return c.NoContent(http.StatusAccepted)
}

// ISUのコンディションの文字列がcsv形式になっているか検証
func isValidConditionFormat(conditionStr string) bool {

	keys := []string{"is_dirty=", "is_overweight=", "is_broken="}
	const valueTrue = "true"
	const valueFalse = "false"

	idxCondStr := 0

	for idxKeys, key := range keys {
		if !strings.HasPrefix(conditionStr[idxCondStr:], key) {
			return false
		}
		idxCondStr += len(key)

		if strings.HasPrefix(conditionStr[idxCondStr:], valueTrue) {
			idxCondStr += len(valueTrue)
		} else if strings.HasPrefix(conditionStr[idxCondStr:], valueFalse) {
			idxCondStr += len(valueFalse)
		} else {
			return false
		}

		if idxKeys < (len(keys) - 1) {
			if conditionStr[idxCondStr] != ',' {
				return false
			}
			idxCondStr++
		}
	}

	return (idxCondStr == len(conditionStr))
}

func getIndex(c echo.Context) error {
	return c.File(frontendContentsPath + "/index.html")
}

func initTrend() error {

	characterList := []string{
		"いじっぱり", "うっかりや", "おくびょう", "おだやか", "おっとり", "おとなしい", "がんばりや", "きまぐれ",
		"さみしがり", "しんちょう", "すなお", "ずぶとい", "せっかち", "てれや", "なまいき", "のうてんき",
		"のんき", "ひかえめ", "まじめ", "むじゃき", "やんちゃ", "ゆうかん", "ようき", "れいせい", "わんぱく",
	}

	res := []TrendResponse{}

	for _, character := range characterList {
		isuList := []Isu{}
		err := db.Select(&isuList,
			"SELECT * FROM `isu` WHERE `character` = ?",
			character,
		)
		if err != nil {
			goLog.Printf("db error: %v", err)
			return err
		}

		characterInfoIsuConditions := []*TrendCondition{}
		characterWarningIsuConditions := []*TrendCondition{}
		characterCriticalIsuConditions := []*TrendCondition{}
		for _, isu := range isuList {
			conditions := []IsuCondition{}
			err = db.Select(&conditions,
				"SELECT * FROM `isu_condition` WHERE `jia_isu_uuid` = ? ORDER BY timestamp DESC LIMIT 1",
				isu.JIAIsuUUID,
			)
			if err != nil {
				goLog.Printf("db error: %v", err)
				return err
			}

			if len(conditions) > 0 {
				isuLastCondition := conditions[0]
				trendCondition := TrendCondition{
					ID:        isu.ID,
					Timestamp: isuLastCondition.Timestamp.Unix(),
				}
				switch isuLastCondition.Level {
				case "info":
					characterInfoIsuConditions = append(characterInfoIsuConditions, &trendCondition)
				case "warning":
					characterWarningIsuConditions = append(characterWarningIsuConditions, &trendCondition)
				case "critical":
					characterCriticalIsuConditions = append(characterCriticalIsuConditions, &trendCondition)
				}
			}

		}

		sort.Slice(characterInfoIsuConditions, func(i, j int) bool {
			return characterInfoIsuConditions[i].Timestamp > characterInfoIsuConditions[j].Timestamp
		})
		sort.Slice(characterWarningIsuConditions, func(i, j int) bool {
			return characterWarningIsuConditions[i].Timestamp > characterWarningIsuConditions[j].Timestamp
		})
		sort.Slice(characterCriticalIsuConditions, func(i, j int) bool {
			return characterCriticalIsuConditions[i].Timestamp > characterCriticalIsuConditions[j].Timestamp
		})
		res = append(res,
			TrendResponse{
				Character: character,
				Info:      characterInfoIsuConditions,
				Warning:   characterWarningIsuConditions,
				Critical:  characterCriticalIsuConditions,
			})
	}

	omTrendRes.Set(res)

	return nil
}
