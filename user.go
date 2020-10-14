package main

import (
	"log"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"
)

// User defines the struct of a user
type User struct {
	gorm.Model
	Username string `json:"username" form:"user"`
	Password string `json:"password" form:"password"`
	Email    string `json:"email" form:"email"`
	Gender   string `json:"gender" form:"gender"`
	Remarks  string `json:"remarks" form:"remarks"`
}

// UserAccount defines the struct of a account belongs to user
type UserAccount struct {
	gorm.Model
	UserID    int
	AccountID int
	Blocked   int
}

// CheckPassword user infos
func (user *User) CheckPassword() bool {
	tmpPassword := user.Password
	res := db.Where("username = ? OR email = ?", user.Username, user.Email).First(user)
	if res.RowsAffected > 0 {
		if password, err := decrypt(user.Password, encryptKey); err == nil {
			return password == tmpPassword
		}
	}
	return false
}

//Validate valids user infos
func (user *User) Validate() bool {
	if len(user.Email) < 1 || len(user.Username) < 1 || len(user.Password) < 1 {
		return false
	}
	return true
}

// CreateToken create a new token for user
func (user *User) CreateToken() string {
	expireTime := time.Now().Add(time.Hour).Format("20060102150405")
	userID := strconv.Itoa(int(user.ID))
	if en, err := encrypt(userID+":"+expireTime, encryptKey); err == nil {
		return en
	}
	return ""
}

// CheckToken will check the token if it expired
func (user *User) CheckToken(token string) bool {
	if len(token) < 1 {
		return false
	}
	deToken, err := decrypt(token, encryptKey)
	if err != nil {
		log.Println(err)
		return false
	}
	userInfos := strings.Split(deToken, ":")
	if now, err := strconv.Atoi(time.Now().Format("20060102150405")); err == nil {
		if userID, err := strconv.Atoi(userInfos[0]); err == nil {
			if userID == int(user.ID) {
				if expireTime, err := strconv.Atoi(userInfos[1]); err == nil {
					if now < expireTime {
						return true
					}
				}
			}
		}
	}
	return false
}
