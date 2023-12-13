package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type AppClaims struct {
	Id   string
	Name string
	jwt.RegisteredClaims
}

type AppResponse struct {
	Token string
}

func main() {

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		claims := AppClaims{
			Id:   "1583926",
			Name: "John Doe",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(2 * time.Minute)),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, _ := token.SignedString([]byte("SECRET"))

		json.NewEncoder(w).Encode(AppResponse{
			Token: tokenString,
		})

	})

	http.HandleFunc("/renovar-token", func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Token no proporcionado en el encabezado Authorization", http.StatusUnauthorized)
			return
		}

		// Verificar el token expirado
		token, err := jwt.ParseWithClaims(tokenString, &AppClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte("SECRET"), nil
		})

		if err != nil {
			http.Error(w, fmt.Sprintf("Error al analizar el token: %v", err), http.StatusUnauthorized)
			return
		}

		// Verificar si el token expirado es válido
		if claims, ok := token.Claims.(*AppClaims); ok && token.Valid {
			// Extender el tiempo de expiración del token
			claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Hour * 24)) // Tiempo de expiración extendido (por ejemplo, 24 horas)

			// Firmar el nuevo token
			nuevoToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			nuevoTokenString, err := nuevoToken.SignedString([]byte("SECRET"))
			if err != nil {
				http.Error(w, fmt.Sprintf("Error al firmar el nuevo token: %v", err), http.StatusInternalServerError)
				return
			}

			json.NewEncoder(w).Encode(AppResponse{
				Token: nuevoTokenString,
			})
		} else {
			http.Error(w, "Token expirado no válido", http.StatusUnauthorized)
		}
	})

	http.ListenAndServe(":8081", nil)

}
