(ns tiny-auth.utils
  (:require  [clojure.data.codec.base64 :as b64]
             [clj-time.coerce :as c]
             [buddy.hashers :as hashers]
             [clojure.data.json :as json]
             [buddy.sign.jwt :as jwt]
             [clojure.string :as string]
             [clj-time.core :as time])
  (:import java.security.MessageDigest
           java.math.BigInteger))

(defn from-database-date [date]
  (if (instance? java.util.Date date) (c/from-date date) date))

(defn string->uuid
  [s]
  (if (uuid? s) s
      (do
        (assert (string? s) (str "Not a string passed as a UUID: " s))
        (. java.util.UUID fromString s))))

(defn fmap-keys
  [f m]
  (into (empty m) (for [[k v] m] [(f k) v])))

 ; ----------------- code from  https://gist.github.com/ggeoffrey/b72ed568be4914a990790ea6b09c2c66 -----------------

(defn decode-b64 [str] (String. (b64/decode (.getBytes str))))

(defn encode-b64 [str] (String. (b64/encode (.getBytes str))))

(defn parse-json [s]
  ; Autor of code from github wrote that he got some tokens from AWS Cognito where the last '}' was missing in the payload (in our case it is also true)
  (let [clean-str (if (string/ends-with? s "}") s (str s "}"))]
    (json/read-str clean-str :key-fn keyword)))

(defn validate-token [config token header]
  (try
    (let [{kid :kid alg :alg} header
          v-alg (-> alg string/lower-case keyword)]
      (jwt/unsign token (get (:apple-secrets config) kid) {:alg v-alg}))
    (catch Throwable _
      false)))

; ------------------------------------------------------------------------------------------------------------------

(defn decode [token]
  (let [[header payload _] (string/split token #"\.")]
    {:header  (parse-json (decode-b64 header))
     :payload (parse-json (decode-b64 payload))}))

(defn encrypt-password
  "Salt is included in the algorithm"
  [password]
  (hashers/derive password {:alg :bcrypt+sha512}))

(defn check-password
  [password hash]
  (hashers/check password hash))

(defn md5
  [^String s]
  (->> s
       .getBytes
       (.digest (MessageDigest/getInstance "MD5"))
       (BigInteger. 1)
       (format "%032x")))

(defn generate-confirmation-code
  ([] (generate-confirmation-code 6))
  ([n]
   (let [digits (map char (range 48 58))
         capital-letters (map char (range 65 91))
         small-letters (map char (range 97 123))
         chars (concat digits capital-letters small-letters)
         code (take n (repeatedly #(rand-nth chars)))]
     (reduce str code))))

(defn generate-phone-confirmation-code [n]
  (let [digits (map char (range 48 58))
        code (take n (repeatedly #(rand-nth digits)))]
    (reduce str code)))

(defn generate-token
  [config user session-id]
  (let [session-params (if session-id
                         {:session-id (str session-id)}
                         {})
        claims
        (merge session-params
               {:user (str (:app/uuid user))
                :exp (time/plus
                      (time/now)
                      (time/seconds (eval (:token-expiry config))))})
        jwt-private-key (-> config :secrets :jwt-private-key)]
    (jwt/sign claims jwt-private-key {:alg :es512})))

(defn generate-password-token
  [config user]
  (let [claims
        {:password-recovery-user (str (:app/uuid user))
         :exp (time/plus
               (time/now)
               (time/seconds (eval  (:password-token-expiry config))))
         :password-hash (md5 (:user/password-hash user))}
        jwt-private-key (-> config :secrets :jwt-private-key)]
    (jwt/sign claims jwt-private-key {:alg :es512})))

(defn generate-reset-phone-number-token
  [config user]
  (let [claims
        {:phone-number-reset-user (str (:app/uuid user))
         :exp (time/plus
               (time/now)
               (time/seconds (eval (:password-token-expiry config))))}
        jwt-private-key (-> config :secrets :jwt-private-key)]
    (jwt/sign claims jwt-private-key {:alg :es512})))

(defn generate-confirmation-token
  [config user]
  (let [claims
        {:user-confirmed (str (:app/uuid user))
         :exp (time/plus
               (time/now)
               (time/seconds (eval (:confirmation-token-expiry config))))}
        jwt-private-key (-> config :secrets :jwt-private-key)]
    (jwt/sign claims jwt-private-key {:alg :es512})))

(defn generate-universal-token
  [config extra-claims expiry-in-seconds]
  (let [claims
        (merge {:exp (time/plus
                     (time/now)
                     (time/seconds expiry-in-seconds))} extra-claims)
        jwt-private-key (-> config :secrets :jwt-private-key)]
    (jwt/sign claims jwt-private-key {:alg :es512})))

(defn unsign-token
  [config token]
  (jwt/unsign token (-> config :secrets :jwt-public-key) {:alg :es512
                                                          :skip-validation true}))

(defn get-check-code-frequency-fn [{:keys [last-failed-field
                                           failed-count-field
                                           env-delay-field]}]
  (fn [config user]
    (let [last-failed (from-database-date (last-failed-field user))
          failed-count (failed-count-field user)]
      (or (not last-failed)
          (not failed-count)
          (< failed-count 3)
          (>=
           (time/in-seconds (time/interval last-failed (time/now)))
           (eval (env-delay-field config)))))))

(def check-login-frequency
  (get-check-code-frequency-fn
   {:last-failed-field :user/last-failed-login
    :failed-count-field :user/failed-logins-count
    :env-delay-field :login-delay}))

(def check-confirmation-code-frequency
  (get-check-code-frequency-fn
   {:last-failed-field :user/last-failed-confirmation
    :failed-count-field :user/failed-confirmations-count
    :env-delay-field :login-delay}))

(def check-password-reset-code-frequency
  (get-check-code-frequency-fn
   {:last-failed-field :user/last-failed-password-reset
    :failed-count-field :user/failed-password-reset-count
    :env-delay-field :reset-delay}))

(def check-phone-number-change-code-frequency
  (get-check-code-frequency-fn
   {:last-failed-field :user/last-failed-phone-number-change
    :failed-count-field :user/failed-phone-number-change-count
    :env-delay-field :reset-delay}))

(def check-phone-number-claim-code-frequency
  (get-check-code-frequency-fn
   {:last-failed-field :user/last-failed-phone-number-claim
    :failed-count-field :user/failed-phone-number-claim-count
    :env-delay-field :reset-delay}))

(def check-phone-number-reset-code-frequency
  (get-check-code-frequency-fn
   {:last-failed-field :user/last-failed-phone-number-reset
    :failed-count-field :user/failed-phone-number-reset-count
    :env-delay-field :reset-delay}))

(defn check-frequency [env-delay-field config last-date]
  (try
    (let [lc (from-database-date last-date)]
      (>=
       (time/in-seconds (time/interval lc (time/now)))
       (eval (env-delay-field config))))
    (catch Exception _
      false)))

(def check-reset-frequency
  (partial check-frequency :reset-delay))

(def check-phone-number-reset-email-frequency
  (partial check-frequency :reset-delay))

(def check-email-frequency
  (partial check-frequency :email-update-delay))

(defn check-code-expiry [env-delay-field config last-date]
  (try
    (let [lc (from-database-date last-date)]
      (<=
       (time/in-seconds (time/interval lc (time/now)))
       (eval (env-delay-field config))))
    (catch Exception _
      false)))

(def check-password-reset-code-expiry
  (partial check-code-expiry :password-token-expiry))

(def check-phone-number-change-code-expiry
  (partial check-code-expiry :password-token-expiry))

(def check-phone-number-claim-code-expiry
  (partial check-code-expiry :password-token-expiry))

(def check-phone-number-reset-code-expiry
  (partial check-code-expiry :password-token-expiry))

(defn correct-code? [config phone-number code correct-code]
  (let [fixed-phone-numbers (:phone-numbers-with-fixed-code config)
        fixed-code (or (:default-confirm-code config)
                       (get fixed-phone-numbers phone-number))]
    (and code
         (or (= code correct-code)
             (= code fixed-code)
             (:accept-all-codes config)))))
