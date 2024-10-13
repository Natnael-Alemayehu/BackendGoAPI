package main

import (
	"errors"
	"net/http"
	"time"

	"natenine.backend.API/internal/data"
	"natenine.backend.API/internal/validator"
)

func (app *application) registerUserHandler(w http.ResponseWriter, r *http.Request) {

	// This struct holds the data that comes from the body
	var input struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	// Parse the request body into the anonymous struct.
	err := app.readJSON(w, r, &input)
	if err != nil {
		app.badBadRequestResponse(w, r, err)
		return
	}

	user := &data.User{
		Name:      input.Name,
		Email:     input.Email,
		Activated: false,
	}

	err = user.Password.Set(input.Password)
	if err != nil {
		app.serveErrorResponse(w, r, err)
		return
	}

	v := validator.New()

	if data.ValidateUser(v, user); !v.Valid() {
		app.failedValidationResponse(w, r, v.Errors)
		return
	}

	err = app.models.Users.Insert(user)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrDuplicateEmail):
			v.AddError("email", "a user with this email address already exists")
			app.failedValidationResponse(w, r, v.Errors)
		default:
			app.serveErrorResponse(w, r, err)
		}
		return
	}

	// Add the "movies:read" permission for every new user
	err = app.models.Permissions.AddForUser(user.ID, "movies:read")
	if err != nil {
		app.serveErrorResponse(w, r, err)
		return
	}

	token, err := app.models.Tokens.New(user.ID, 3*24*time.Hour, data.ScopeActivation)
	if err != nil {
		app.serveErrorResponse(w, r, err)
		return
	}

	// Sending the email in another goroutine
	app.background(func() {
		data := map[string]any{
			"activationToken": token.Plaintext,
			"UserID":          user.ID,
		}
		err = app.mailer.Send(user.Email, "user_welcome.tmpl.html", data)
		if err != nil {
			app.logger.PrintError(err, nil)
		}
	})

	err = app.writeJSON(w, http.StatusAccepted, envelope{"user": user}, nil)
	if err != nil {
		app.serveErrorResponse(w, r, err)
	}
}

func (app *application) activateUserHandler(w http.ResponseWriter, r *http.Request) {

	var input struct {
		TokenPlainText string `json:"token"`
	}

	err := app.readJSON(w, r, &input)
	if err != nil {
		app.badBadRequestResponse(w, r, err)
		return
	}

	v := validator.New()

	if data.ValidateTokenPlaintext(v, input.TokenPlainText); !v.Valid() {
		app.failedValidationResponse(w, r, v.Errors)
		return
	}

	user, err := app.models.Users.GetForToken(data.ScopeActivation, input.TokenPlainText)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrRecordNotFound):
			v.AddError("token", "invalid or expired activation token")
			app.failedValidationResponse(w, r, v.Errors)
		default:
			app.serveErrorResponse(w, r, err)
		}
		return
	}

	// Update the user activation status
	user.Activated = true

	// Save the updated user record in our database, checking for any edit conflicts
	err = app.models.Users.Update(user)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrEditConflict):
			app.editConflictResponse(w, r)
		default:
			app.serveErrorResponse(w, r, err)
		}
		return
	}

	// If everything is successfully, then we delete all activation tokens for the user
	err = app.models.Tokens.DeleteForAllUser(data.ScopeActivation, user.ID)
	if err != nil {
		app.serveErrorResponse(w, r, err)
		return
	}

	err = app.writeJSON(w, http.StatusOK, envelope{"user": user}, nil)
	if err != nil {
		app.serveErrorResponse(w, r, err)
	}

}

func (app *application) updateUserPasswordHander(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Password       string `json:"password"`
		TokenPlainText string `json:"token"`
	}
	err := app.readJSON(w, r, &input)
	if err != nil {
		app.badBadRequestResponse(w, r, err)
		return
	}

	v := validator.New()

	data.ValidatePassowrdPlaintext(v, input.Password)
	data.ValidateTokenPlaintext(v, input.TokenPlainText)

	if !v.Valid() {
		app.failedValidationResponse(w, r, v.Errors)
		return
	}

	user, err := app.models.Users.GetForToken(data.ScopePasswordReset, input.TokenPlainText)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrRecordNotFound):
			v.AddError("token", "invalid or expired password reset token")
			app.failedValidationResponse(w, r, v.Errors)
		default:
			app.serveErrorResponse(w, r, err)
		}
		return
	}

	err = user.Password.Set(input.Password)
	if err != nil {
		app.serveErrorResponse(w, r, err)
		return
	}

	err = app.models.Users.Update(user)
	if err != nil {
		switch {
		case errors.Is(err, data.ErrEditConflict):
			app.editConflictResponse(w, r)
		default:
			app.serveErrorResponse(w, r, err)
		}
		return
	}

	err = app.models.Tokens.DeleteForAllUser(data.ScopePasswordReset, user.ID)
	if err != nil {
		app.serveErrorResponse(w, r, err)
		return
	}

	env := envelope{"message": "your password was successfully reset"}

	err = app.writeJSON(w, http.StatusOK, env, nil)
	if err != nil {
		app.serveErrorResponse(w, r, err)
	}
}
