(ns tiny-auth.validators
  (:require [clojure.data.json :refer [read-str]]
            [clj-time.coerce :as c]
            [tiny-auth.db.user :as db-user]
            [failjure.core :as f]
            [phone-number.core :as phone]
            [clj-time.core :as time]))

(def code-to-language {"en" "English"
                       "ar" "Arabic"})

(defn string->uuid [str-uuid field-name]
  (try
    (if (uuid? str-uuid) str-uuid
        (do
          (assert (string? str-uuid) (str "Not a string passed as a UUID: " str-uuid))
          (. java.util.UUID fromString str-uuid)))
    (catch Exception _
      (f/fail
       {:response :validators/string->uuid
        :title [field-name]}))))

(defn language-code [language-code]
  (or (get code-to-language language-code)
      (f/fail {:response :validators/language-code})))

(defn email [config raw-email]
  (if (re-matches (re-pattern (:email-regex config)) raw-email)
    raw-email
    (f/fail {:response :validators/email})))

(defn user-uniqueness-email [config email snapshot]
  (when (db-user/get-by-id config snapshot :user/email email)
    (f/fail {:response :validators/user-uniqueness})))

(defn password-strength [password]
  (if (and
       (>= (count password) 8)
       (<= (count password) 200))
    password
    (f/fail {:response :validators/password-strength})))

(defn string-size [s max-size-in-bytes field-name]
  (let [size (alength (.getBytes s "UTF-8"))]
    (if (< size max-size-in-bytes)
      s
      (f/fail {:response :validators/string-size
               :title [field-name]
               :message [max-size-in-bytes]}))))

(defn json-string [txt]
  (try
    (read-str txt :key-fn keyword)
    (catch Exception _
      (f/fail {:response :validators/json-string}))))

(defn user-from-string-uuid [config string-uuid snapshot]
  (let [user (db-user/get-by-string-uuid config snapshot string-uuid)]
    (if (:user/username user)
      user
      (f/fail {:response :validators/user-from-string-uuid}))))

(defn role [role]
  (if (contains? #{"user" "admin" "superadmin"} role)
    (keyword "role" role)
    (f/fail {:response :validators/validate-role})))

(defn language [target-language]
  (if (contains? #{"en" "ar"} target-language)
    target-language
    (f/fail {:response :validators/language})))

(defn phone [phone]
  (let [phone-info (try (phone/info phone) (catch Throwable _ nil))
        valid-phone-info? (and (:phone-number/calling-code phone-info)
                               (:phone-number/valid? phone-info))
        valid-phone-number? (re-matches #"^\+[1-9][0-9]{2,3}[0-9]{5,12}$" phone)]
    (if (and valid-phone-info?
             valid-phone-number?)
      phone
      (f/fail {:response :validators/phone}))))

(defn iss [issuer]
  (if (= issuer "https://appleid.apple.com")
    issuer
    (f/fail {:response :validators/iss})))

(defn aud [config audience]
  (if (contains? (:application-bundle-ids config) audience)
    audience
    (f/fail {:response :validators/aud})))

(defn exp [exp-epoch]
  (if (and exp-epoch (time/before? (time/now) (c/from-epoch exp-epoch)))
    exp-epoch
    (f/fail {:response :validators/exp})))