package users

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
	"users/jwt"
)

var manage jwt.AuthManager

func UserIdentityMiddleware() gin.HandlerFunc {

	return func(ctx *gin.Context) {

		value := ctx.GetHeader(AuthorizationHeader)
		if value == "" {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header is empty",
			})
			return
		}
		valueParts := strings.Split(value, " ")

		if len(valueParts) < 2 || valueParts[0] != TypeJWT {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid authorization header",
			})
		}
		claims, err := manage.ParseToken(valueParts[1])
		if err != nil {
			return
		}
		ctx.Set(UserSessionKeyName, claims)
	}
}

func GetUserFromContext(c *gin.Context) *jwt.TokenClaims {
	context, exists := c.Get(UserSessionKeyName)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User context is empty",
		})
		return nil
	}
	return context.(*jwt.TokenClaims)
}
