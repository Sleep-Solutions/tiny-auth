# tiny-auth

A Clojure library that implements basic authorization endpoints. Each endpoint is a function that returns a map:
```
{:response response 
 :transaction transaction}
```
Where transaction is a Datomic transaction and response is a map (ready `200 OK` response) or a keyword (description of an error - e.g. `:auth-confirm-token/error-code-bad-token`). 

## Installation

Leiningen coordinates:
```clojure
[tiny-auth/tiny-auth "0.1.0"]
```

In order to use `tiny-auth`, you have to add a similar line to `project.clj`:
```
:repositories [["github" {:url "https://maven.pkg.github.com/spinneyio/tiny-auth"
                          :username "private-token"
                          :password :env/GITHUB_TOKEN
                          :sign-releases false}]]
```

You can find more informations about private GitHub Packages [here](https://dev.to/primenumsdev/publish-clojure-library-as-private-github-package-3km).

## Configuration
Default config:
```
{:pull datomic/pull
 :q datomic/q
 :db datomic/db
 :conn datomic/conn
 :secrets {:jwt-public-key "your-jwt-public-key" 
           :jwt-private-key "your-jwt-private-key"}
 :email-regex "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b"
 :token-expiry (* 14 24 3600) ; 14 days
 :password-token-expiry (* 2 3600) ; 2 hours 
 :confirmation-token-expiry (* 2 3600) ; 2 hours 
 :login-delay (* 5 60) ; 5 minutes
 :reset-delay (* 5 60) ; 5 minutes
 :application-bundle-ids #{} ;; Only for login-with-apple.
 :phone-numbers-with-fixed-code {}
 :default-confirm-code "1111" ;; Default code for phone-number endpoints.
 :get-update-code-fn (constantly [])
 :signup-hooks-transaction (constantly [])
 :password-reset-initiate-hooks (constantly {:success true :transaction []})
 :password-reset-confirm-hooks-transaction (constantly [])
 :confirm-hooks (constantly {:success true :transaction []})
 :check-user-role (constantly true)
 :change-confirm-code-hooks-transaction (constantly [])
 :initiate-claim-hooks-transaction (constantly [])
 :claim-confirm-code-hooks-transaction (constantly [])
 :initiate-reset-hooks-transaction (constantly [])
 :reset-confirm-code-hooks-transaction (constantly [])
 :create-account-with-phone-number-hooks-transaction (constantly [])
 :add-email-hooks-transaction (constantly [])}
```

Parameter with `-hooks-transaction` suffix should be a function that returns datomic transaction. 
Parameter with `-hooks` suffix should be a function that returns map with two fields: `success` and `transaction`. 

## Example

```
(defn integrate-endpoint [tiny-auth-fn request params]
  (db/with-transaction [(:conn tiny-auth-config) nil request]
    (let [{:keys [response transaction] :as tiny-auth-result} (tiny-auth-fn tiny-auth-config params)]
      (when (seq transaction)
        (transact transaction))
      (if (map? response)
        response
        (tiny-auth-error->error-response tiny-auth-result)))))

(POST "/login/google" request
    :body-params [google-token :- String
                  google-user :- String
                  session-id :- String
                  {session-language :- String "en"}]
    (integrate-endpoint
     ta-google/login-with-google
     request
     {:google-token google-token
      :google-user google-user
      :session-id session-id
      :session-language session-language}))
```


## Deployment

To deploy new version - change release number in `project.clj` and then manually run github actions `publish package` workflow from GitHub web application.

