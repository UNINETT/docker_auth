/*
   Copyright 2016 Cesanta Software Ltd, UNINETT AS

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       https://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package authn

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang/glog"
)

type DataportenAuthConfig struct {
	Organization     string        `yaml:"organization,omitempty"`
	ClientId         string        `yaml:"client_id,omitempty"`
	ClientSecret     string        `yaml:"client_secret,omitempty"`
	ClientSecretFile string        `yaml:"client_secret_file,omitempty"`
	RedirectURI      string        `yaml:"redirect_uri,omitempty"`
	TokenDB          string        `yaml:"token_db,omitempty"`
	HTTPTimeout      time.Duration `yaml:"http_timeout,omitempty"`
	RevalidateAfter  time.Duration `yaml:"revalidate_after,omitempty"`
}

type DataportenAuthRequest struct {
	Action string `json:"action,omitempty"`
	Code   string `json:"code,omitempty"`
	Token  string `json:"token,omitempty"`
}

type DataportenTokenUser struct {
	User struct {
		Userid string `json:"userid,omitempty"`
		Email string `json:"email,omitempty"`
	} `json:"user"`
}

type DataportenAuth struct {
	config *DataportenAuthConfig
	db     TokenDB
	client *http.Client
	tmpl   *template.Template
}

func NewDataportenAuth(c *DataportenAuthConfig) (*DataportenAuth, error) {
	db, err := NewTokenDB(c.TokenDB)
	if err != nil {
		return nil, err
	}
	glog.Infof("Dataporten auth token DB at %s", c.TokenDB)
	return &DataportenAuth{
		config: c,
		db:     db,
		client: &http.Client{Timeout: 10 * time.Second},
		tmpl:   template.Must(template.New("dataporten_auth").Parse(string(MustAsset("data/dataporten_auth.tmpl")))),
	}, nil
}

func (da *DataportenAuth) doDataportenAuthPage(rw http.ResponseWriter, req *http.Request) {
	if err := da.tmpl.Execute(rw, struct{ ClientId string }{ClientId: da.config.ClientId}); err != nil {
		http.Error(rw, fmt.Sprintf("Template error: %s", err), http.StatusInternalServerError)
	}
}

func (da *DataportenAuth) DoDataportenAuth(rw http.ResponseWriter, req *http.Request) {
	code := req.URL.Query().Get("code")
	redirect_uri := req.URL.Query().Get("redirect_uri")
	glog.Infof("req.URL: %s, (%+v)", req.URL, req.URL)
	glog.Infof("req.URL.Query(): %+v", req.URL.Query())

	if code != "" {
		da.doDataportenAuthCreateToken(rw, code, redirect_uri)
	} else if req.Method == "GET" {
		da.doDataportenAuthPage(rw, req)
		return
	}
}

func (da *DataportenAuth) doDataportenAuthCreateToken(rw http.ResponseWriter, code string, redirect_uri string) {
	data := url.Values{
		"client_id":     []string{da.config.ClientId},
		"client_secret": []string{da.config.ClientSecret},
		"code":          []string{string(code)},
		"grant_type":    []string{"authorization_code"},
		"redirect_uri":  []string{da.config.RedirectURI},
	}
	body := bytes.NewBufferString(data.Encode())
	req, err := http.NewRequest("POST", "https://auth.dataporten.no/oauth/token", body)
	if err != nil {
		http.Error(rw, fmt.Sprintf("Error creating request to Dataporten auth backend: %s", err), http.StatusServiceUnavailable)
		return
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := da.client.Do(req)
	if err != nil {
		http.Error(rw, fmt.Sprintf("Error talking to Dataporten auth backend: %s", err), http.StatusServiceUnavailable)
		return
	}
	codeResp, _ := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	glog.V(2).Infof("Code to token resp: %s", strings.Replace(string(codeResp), "\n", " ", -1))

	var c2t CodeToTokenResponse
	err = json.Unmarshal(codeResp, &c2t)
	if err != nil || c2t.Error != "" || c2t.ErrorDescription != "" {
		var et string
		if err != nil {
			et = err.Error()
		} else {
			et = fmt.Sprintf("%s: %s", c2t.Error, c2t.ErrorDescription)
		}
		http.Error(rw, fmt.Sprintf("Failed to get token: %s", et), http.StatusBadRequest)
		return
	}

	user, err := da.validateAccessToken(c2t.AccessToken)
	if err != nil {
		glog.Errorf("Newly-acquired token is invalid: %+v %s", c2t, err)
		http.Error(rw, "Newly-acquired token is invalid", http.StatusInternalServerError)
		return
	}

	glog.Infof("New Dataporten auth token for %s", user)

	v := &TokenDBValue{
		TokenType:   c2t.TokenType,
		AccessToken: c2t.AccessToken,
		ValidUntil:  time.Now().Add(da.config.RevalidateAfter),
	}
	dp, err := da.db.StoreToken(user, v, true)
	if err != nil {
		glog.Errorf("Failed to record server token: %s", err)
		http.Error(rw, "Failed to record server token: %s", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(rw, `Server logged in; now run "docker login", use %s as login and %s as password.`, user, dp)
}

func (da *DataportenAuth) validateAccessToken(token string) (user string, err error) {
	req, err := http.NewRequest("GET", "https://auth.dataporten.no/userinfo", nil)
	if err != nil {
		err = fmt.Errorf("could not create request to get information for token %s: %s", token, err)
		return
	}
	req.Header.Add("Authorization", fmt.Sprintf("bearer %s", token))
	req.Header.Add("Accept", "application/json")

	resp, err := da.client.Do(req)
	if err != nil {
		err = fmt.Errorf("could not verify token %s: %s", token, err)
		return
	}
	body, _ := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	var ti DataportenTokenUser
	err = json.Unmarshal(body, &ti)
	if err != nil {
		err = fmt.Errorf("could not unmarshal token user info %q: %s", string(body), err)
		return
	}
	glog.V(2).Infof("Token user info: %+v", strings.Replace(string(body), "\n", " ", -1))
	glog.V(2).Infof("Token user info: %+v", ti)

	err = da.checkOrganization(token, ti.User.Email)
	if err != nil {
		err = fmt.Errorf("could not validate organization: %s", err)
		return
	}

	return ti.User.Email, nil
}

func (da *DataportenAuth) checkOrganization(token, user string) (err error) {
	return nil
}

func (da *DataportenAuth) validateServerToken(user string) (*TokenDBValue, error) {
	v, err := da.db.GetValue(user)
	if err != nil || v == nil {
		if err == nil {
			err = errors.New("no db value, please sign out and sign in again.")
		}
		return nil, err
	}
	tokenUser, err := da.validateAccessToken(v.AccessToken)
	if err != nil {
		glog.Warningf("Token for %q failed validation: %s", user, err)
		return nil, fmt.Errorf("server token invalid: %s", err)
	}
	if tokenUser != user {
		glog.Errorf("token for wrong user: expected %s, found %s", user, tokenUser)
		return nil, fmt.Errorf("found token for wrong user")
	}
	v.ValidUntil = time.Now().Add(da.config.RevalidateAfter)
	texp := v.ValidUntil.Sub(time.Now())
	glog.V(1).Infof("Validated Dataporten auth token for %s (exp %d)", user, int(texp.Seconds()))
	return v, nil
}

func (da *DataportenAuth) Authenticate(user string, password PasswordString) (bool, Labels, error) {
	err := da.db.ValidateToken(user, password)
	if err == ExpiredToken {
		_, err = da.validateServerToken(user)
		if err != nil {
			return false, nil, err
		}
	} else if err != nil {
		return false, nil, err
	}
	return true, nil, nil
}

func (da *DataportenAuth) Stop() {
	da.db.Close()
	glog.Info("Token DB closed")
}

func (da *DataportenAuth) Name() string {
	return "Dataporten"
}
