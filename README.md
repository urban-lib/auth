## Jwt auth and middlewares

```go

package main

import (
	"github.com/gin-gonic/gin"
	"github.com/urban-lib/auth/jwt"
	"github.com/urban-lib/auth"
	"log"
	"net/http"
	"os"
	"time"
)

func init() {
	_ = os.Setenv("JWTSecret", ")(*&OYFUGVFDSEU%R^IUm,louy8tyCGHpo7itdyfc")
	_ = os.Setenv("JWTSuperSecret", "oiugyuvjbl;op978tyghbnklip8oi7u6tgoi987^TYGH")
}

func main() {
	if err := jwt.NewToken(15*time.Minute, 72*time.Hour); err != nil {
		log.Println(err.Error())
	}
	router := gin.New()
	router.Use(auth.UserIdentityMiddleware())
	router.GET("/ping", ping)
	if err := router.Run(); err != nil {
		log.Fatalf(err.Error())
	}
}

func ping(c *gin.Context) {
	userClaims := auth.GetUserFromContext(c)
	c.JSON(http.StatusOK, gin.H{
		"success": "true",
		"claims": userClaims,
    })
}

```