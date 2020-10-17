package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var db *gorm.DB

func init() {
	dsn := "root:qWezy0020@tcp(127.0.0.1:3306)/gotochat?charset=utf8mb4&parseTime=True&loc=Local"
	var err error
	db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}
}
func main() {
	r := gin.Default()
	r.Use(cors())
	api := r.Group("/api")
	api.Use(func(c *gin.Context) {
		userIDStr := c.Query("user_id")
		token := c.Query("token")
		var user User
		userID, _ := strconv.Atoi(userIDStr)
		user.ID = uint(userID)
		res := db.First(&user)
		if res.Error != nil || !user.CheckToken(token) {
			c.JSON(401, gin.H{
				"message": "wrong token",
			})
			c.Abort()
		}
	})
	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"hello": "world",
		})
	})
	r.POST("/signin", func(c *gin.Context) {
		var user User
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(400, gin.H{"message": err.Error()})
			return
		}
		if !user.CheckPassword() {
			c.JSON(400, gin.H{
				"message": "wrong password",
			})
			return
		}
		c.JSON(200, gin.H{
			"message": "success",
			"data": &struct {
				Token string `json:"token"`
			}{
				user.CreateToken(),
			},
		},
		)
	})

	r.POST("/signup", func(c *gin.Context) {
		var user User
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(400, gin.H{"message": err.Error()})
			return
		}
		res := db.Where("username = ? OR email = ?", user.Username, user.Email).Take(&user)
		if !errors.Is(res.Error, gorm.ErrRecordNotFound) {
			c.JSON(400, gin.H{
				"message": "duplicated email or username",
			})
			return
		}
		if !user.Validate() {
			c.JSON(400, gin.H{
				"message": "bad request",
			})
			return
		}
		dbPwd, _ := encrypt(user.Password, encryptKey)
		user.Password = dbPwd
		res = db.Create(&user)
		if res.Error == nil {
			c.JSON(200, gin.H{
				"message": "success",
				"data": struct {
					Token string `json:"token"`
					ID    uint   `json:"user_id"`
				}{
					user.CreateToken(),
					user.ID,
				},
			})
			return
		}
		c.JSON(400, gin.H{
			"message": "failed to create user",
		})
	})

	api.GET("user/:id", func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Param("id"))
		var user User
		db.Select("username", "email", "gender", "remarks").Where("id = ?", id).First(&user)
		c.JSON(200, gin.H{
			"data": struct {
				Username string `json:"username"`
				Email    string `json:"email"`
				Gender   string `json:"gender"`
				Remarks  string `json:"remarks"`
			}{
				user.Username,
				user.Email,
				user.Remarks,
				user.Gender,
			},
		})
	})
	api.POST("user/account/:account_id", func(c *gin.Context) {
		id, _ := strconv.Atoi(c.Query("user_id"))
		accountID, _ := strconv.Atoi(c.Param("account_id"))
		if id == accountID {
			c.JSON(400, gin.H{
				"message": "bad request",
			})
			return
		}
		var user User
		res := db.Where("id = ?", accountID).First(&user)
		if res.Error != nil {
			c.JSON(400, gin.H{
				"message": "bad request",
			})
			return
		}
		var userAccount = &UserAccount{
			UserID:    id,
			AccountID: accountID,
			Blocked:   0,
		}
		res = db.Create(&userAccount)
		if res.Error != nil {
			c.JSON(500, gin.H{
				"message": "Internal server error",
			})
			return
		}
		c.JSON(200, gin.H{
			"message": "success",
		})
	})
	r.Run(":80")
}

func cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		method := c.Request.Method
		origin := c.Request.Header.Get("Origin") //请求头部
		var headerKeys []string                  // 声明请求头keys
		for k := range c.Request.Header {
			headerKeys = append(headerKeys, k)
		}
		headerStr := strings.Join(headerKeys, ", ")
		if headerStr != "" {
			headerStr = fmt.Sprintf("access-control-allow-origin, access-control-allow-headers, %s", headerStr)
		} else {
			headerStr = "access-control-allow-origin, access-control-allow-headers"
		}
		if origin != "" {
			c.Header("Access-Control-Allow-Origin", "*") // 可将将 * 替换为指定的域名
			c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, UPDATE")
			c.Header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization")
			c.Header("Access-Control-Expose-Headers", "Content-Length, Access-Control-Allow-Origin, Access-Control-Allow-Headers, Cache-Control, Content-Language, Content-Type")
			c.Header("Access-Control-Allow-Credentials", "true")
		}
		if method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
		}
		c.Next()
	}
}
