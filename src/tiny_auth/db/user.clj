(ns tiny-auth.db.user
  (:require [clojure.data.json :refer [read-str]]
            [tiny-auth.db.core :as db]
            [tiny-auth.utils :as u]))

(def user-schema
  [{:db/ident              :user/username
    :db/valueType          :db.type/string
    :db/cardinality        :db.cardinality/one
    :db/unique             :db.unique/value
    :db/doc                "Username can well be an email address. Uniqueness is ensured"}

   {:db/ident              :user/facebook-id
    :db/valueType          :db.type/string
    :db/cardinality        :db.cardinality/one
    :db/unique             :db.unique/value
    :db/doc                "Unique facebook id if the user has one"}

   {:db/ident              :user/google-id
    :db/valueType          :db.type/string
    :db/cardinality        :db.cardinality/one
    :db/unique             :db.unique/value
    :db/doc                "Unique google id if the user has one"}

   {:db/ident              :user/apple-id
    :db/valueType          :db.type/string
    :db/cardinality        :db.cardinality/one
    :db/unique             :db.unique/value
    :db/doc                "Unique apple id if the user has one"}

   {:db/ident              :user/s3-photo-key
    :db/valueType          :db.type/string
    :db/cardinality        :db.cardinality/one
    :db/unique             :db.unique/value
    :db/doc                "Unique photo key for storing the s3 key"}

   {:db/ident              :user/twitch-id
    :db/valueType          :db.type/string
    :db/cardinality        :db.cardinality/one
    :db/unique             :db.unique/value
    :db/doc                "Unique twitch id if the user has one"}

   {:db/ident              :user/password-hash
    :db/valueType          :db.type/string
    :db/cardinality        :db.cardinality/one
    :db/doc                "Password hash is stored here"}

   {:db/ident              :user/email
    :db/valueType          :db.type/string
    :db/cardinality        :db.cardinality/one
    :db/unique             :db.unique/value
    :db/doc                "Email address"}

   {:db/ident              :user/apns-tokens
    :db/valueType          :db.type/string
    :db/cardinality        :db.cardinality/many
    :db/doc                "APNS tokens of user's devices"}

   {:db/ident              :user/last-reminder
    :db/valueType          :db.type/instant
    :db/cardinality        :db.cardinality/one
    :db/doc                "Date of the last time a password reminder was sent for the user"}

   {:db/ident              :user/last-password-reset
    :db/valueType          :db.type/instant
    :db/cardinality        :db.cardinality/one
    :db/doc                "Date of the last time a password reset email was sent for the user"}

   {:db/ident              :user/last-failed-password-reset
    :db/valueType          :db.type/instant
    :db/cardinality        :db.cardinality/one
    :db/doc                "Last time a password reset failed"}

   {:db/ident              :user/failed-password-reset-count
    :db/valueType          :db.type/long
    :db/cardinality        :db.cardinality/one
    :db/doc                "The number of failed password reset since last password reset request"}

   {:db/ident              :user/last-login
    :db/valueType          :db.type/instant
    :db/cardinality        :db.cardinality/one
    :db/doc                "Last login time"}

   {:db/ident              :user/last-confirmation
    :db/valueType          :db.type/instant
    :db/cardinality        :db.cardinality/one
    :db/doc                "Last time a confirmation email was sent time"}

   {:db/ident              :user/last-failed-confirmation
    :db/valueType          :db.type/instant
    :db/cardinality        :db.cardinality/one
    :db/doc                "Last time a confirmation failed"}

   {:db/ident              :user/failed-confirmations-count
    :db/valueType          :db.type/long
    :db/cardinality        :db.cardinality/one
    :db/doc                "The number of failed confirmations since last confirmation request"}

   {:db/ident              :user/last-failed-login
    :db/valueType          :db.type/instant
    :db/cardinality        :db.cardinality/one
    :db/doc                "Last time a login failed for the user"}

   {:db/ident              :user/failed-logins-count
    :db/valueType          :db.type/long
    :db/cardinality        :db.cardinality/one
    :db/doc                "The number of failed logins since last successful login"}

   {:db/ident              :user/confirmed
    :db/valueType          :db.type/boolean
    :db/cardinality        :db.cardinality/one
    :db/doc                "Confirms that the user was confirmed"}

   {:db/ident              :user/quotas
    :db/valueType          :db.type/ref
    :db/cardinality        :db.cardinality/many
    :db/noHistory          true
    :db/doc                "The list of quota objects"}

   {:db/ident              :user/uploads
    :db/valueType          :db.type/ref
    :db/cardinality        :db.cardinality/many
    :db/doc                "The list of uploads associated with the user"}

   {:db/ident              :user/confirmation-code
    :db/valueType          :db.type/string
    :db/cardinality        :db.cardinality/one
    :db/doc                "A confirmation code user is supposed to type in the app"}

   {:db/ident              :user/password-reset-code
    :db/valueType          :db.type/string
    :db/cardinality        :db.cardinality/one
    :db/doc                "A password reset code user is supposed to type in the app"}

   {:db/ident              :user/role
    :db/valueType          :db.type/ref
    :db/cardinality        :db.cardinality/one
    :db/doc                "User's snapshot role: superadmin, admin or (normal) user."}

   {:db/ident              :user/notification-tokens
    :db/valueType          :db.type/ref
    :db/cardinality        :db.cardinality/many
    :db/doc                "The list of all user's device firebase registration tokens with last date."}

   {:db/ident              :user/sessions
    :db/valueType          :db.type/ref
    :db/cardinality        :db.cardinality/many
    :db/doc                "The list of all user's sessions."}

   {:db/ident              :user/deactivated
    :db/valueType          :db.type/boolean
    :db/cardinality        :db.cardinality/one
    :db/doc                "Confirms that the user's account was deactivated."}

   {:db/ident              :user/additional-data
    :db/valueType          :db.type/string
    :db/cardinality        :db.cardinality/one
    :db/doc                "Additional data (string from json)."}

   {:db/ident              :user/phone-number
    :db/valueType          :db.type/string
    :db/cardinality        :db.cardinality/one
    :db/unique             :db.unique/value
    :db/doc                "Phone number"}

   {:db/ident              :user/last-email-update
    :db/valueType          :db.type/instant
    :db/cardinality        :db.cardinality/one
    :db/doc                "Last time an email was updated for the user"}

   {:db/ident              :user/new-phone-number
    :db/valueType          :db.type/string
    :db/cardinality        :db.cardinality/one
    :db/doc                "If user confirms that phone number it will replace current :user/phone-number."}

   {:db/ident              :user/phone-number-change-code
    :db/valueType          :db.type/string
    :db/cardinality        :db.cardinality/one
    :db/doc                "A phone number change code user is supposed to type in the app"}

   {:db/ident              :user/last-phone-number-change
    :db/valueType          :db.type/instant
    :db/cardinality        :db.cardinality/one
    :db/doc                "Date of the last time a phone number change message was sent for the user."}

   {:db/ident              :user/last-failed-phone-number-change
    :db/valueType          :db.type/instant
    :db/cardinality        :db.cardinality/one
    :db/doc                "Last time a phone number change failed"}

   {:db/ident              :user/failed-phone-number-change-count
    :db/valueType          :db.type/long
    :db/cardinality        :db.cardinality/one
    :db/doc                "The number of failed phone number change code confirmations since last phone number change request"}

   {:db/ident              :user/phone-number-claim-code
    :db/valueType          :db.type/string
    :db/cardinality        :db.cardinality/one
    :db/doc                "A phone number claim code user is supposed to type in the app"}

   {:db/ident              :user/last-phone-number-claim
    :db/valueType          :db.type/instant
    :db/cardinality        :db.cardinality/one
    :db/doc                "Date of the last time a phone number claim message was sent for the user."}

   {:db/ident              :user/last-failed-phone-number-claim
    :db/valueType          :db.type/instant
    :db/cardinality        :db.cardinality/one
    :db/doc                "Last time a phone number claim failed"}

   {:db/ident              :user/failed-phone-number-claim-count
    :db/valueType          :db.type/long
    :db/cardinality        :db.cardinality/one
    :db/doc                "The number of failed phone number claim code confirmations since last phone number change request"}

   {:db/ident              :user/phone-number-reset-code
    :db/valueType          :db.type/string
    :db/cardinality        :db.cardinality/one
    :db/doc                "A phone number claim code user is supposed to type in the app"}

   {:db/ident              :user/last-phone-number-reset-email
    :db/valueType          :db.type/instant
    :db/cardinality        :db.cardinality/one
    :db/doc                "Date of the last time a phone number reset email was sent for the user."}

   {:db/ident              :user/last-phone-number-reset
    :db/valueType          :db.type/instant
    :db/cardinality        :db.cardinality/one
    :db/doc                "Date of the last time a phone number reset sms message was sent for the user."}

   {:db/ident              :user/last-failed-phone-number-reset
    :db/valueType          :db.type/instant
    :db/cardinality        :db.cardinality/one
    :db/doc                "Last time a phone number reset failed"}

   {:db/ident              :user/failed-phone-number-reset-count
    :db/valueType          :db.type/long
    :db/cardinality        :db.cardinality/one
    :db/doc                "The number of failed phone number reset code confirmations since last phone number change request"}

   {:db/ident              :user/last-verification-instructions
    :db/valueType          :db.type/instant
    :db/cardinality        :db.cardinality/one
    :db/doc                "Last time verification instructions were sent."}

         ; User's roles:
   {:db/ident              :role/user}
   {:db/ident              :role/admin}
   {:db/ident              :role/superadmin}])

(defn create-schema [config]
  @((:transact config) (:conn config) user-schema))


(defn get-by-name [config snapshot username]
  (ffirst
   ((:q config)
    '[:find (pull ?e [*])
      :in $ ?username
      :where
      [?e :user/username ?username]]
    snapshot (.toLowerCase ^String username))))

(defn get-by-id [config snapshot id-keyword id]
  (ffirst
   ((:q config)
    '[:find (pull ?e [*])
      :in $ ?id ?id-name
      :where [?e ?id-name ?id]]
    snapshot id id-keyword)))

(defn get-by-string-uuid [config snapshot string-uuid]
  (let [uuid (u/string->uuid string-uuid)]
    ((:pull config) snapshot '[*] [:app/uuid uuid])))

(defn creation-transaction
  [{:keys
    [facebook-id
     email
     password
     twitch-id
     google-id
     confirmed
     confirmation-code
     additional-data
     phone-number]}]
  (let [username (or email facebook-id twitch-id google-id phone-number)
        base-user {:user/username (.toLowerCase ^String username)
                   :user/role :role/user
                   :user/deactivated false}]
    (-> base-user
        (#(if facebook-id (merge % {:user/facebook-id facebook-id}) %))
        (#(if twitch-id (merge % {:user/twitch-id twitch-id}) %))
        (#(if google-id (merge % {:user/google-id google-id}) %))
        (#(if email (merge % {:user/email (.toLowerCase ^String email)}) %))
        (#(if confirmed (merge % {:user/confirmed confirmed}) %))
        (#(if password (merge % {:user/password-hash (u/encrypt-password password)}) %))
        (#(if confirmation-code (merge % {:user/confirmation-code confirmation-code}) %))
        (#(if additional-data (merge % {:user/additional-data additional-data}) %))
        (#(if phone-number (merge % {:user/phone-number phone-number}) %))
        db/create-entity-transaction)))

(defn- claiming-username [phone-number]
  (str "claim-" phone-number))

(defn get-claiming-user [config snapshot phone-number]
  (get-by-name config snapshot (claiming-username phone-number)))

(defn claiming-user-creation-transaction [new-phone-number]
  (db/create-entity-transaction
   {:user/username (claiming-username new-phone-number)
    :user/new-phone-number new-phone-number
    :user/phone-number-claim-code (u/generate-phone-confirmation-code 4)
    :user/role :role/user
    :user/deactivated false
    :user/last-phone-number-claim (java.util.Date.)}))

(defn change-password-transaction [user password]
  [{:db/id user
    :user/password-hash (u/encrypt-password password)}])

(defn change-phone-number-transaction [user]
  [{:user/username (:user/new-phone-number user)
    :user/phone-number (:user/new-phone-number user)
    :app/uuid (:app/uuid user)
    :user/last-phone-number-change (java.util.Date.)
    :user/failed-phone-number-change-count 0}
   [:db/retract (:db/id user) :user/new-phone-number]
   [:db/retract (:db/id user) :user/phone-number-change-code]])

(defn- update-claiming-user-transaction [user]
  [{:user/username (:user/new-phone-number user)
    :user/phone-number (:user/new-phone-number user)
    :app/uuid (:app/uuid user)
    :user/last-phone-number-claim (java.util.Date.)
    :user/failed-phone-number-claim-count 0
    :user/confirmed true}
   [:db/retract (:db/id user) :user/new-phone-number]
   [:db/retract (:db/id user) :user/phone-number-claim-code]])

(defn update-reseting-user-transaction [user]
  [{:user/username (:user/new-phone-number user)
    :user/phone-number (:user/new-phone-number user)
    :app/uuid (:app/uuid user)
    :user/last-phone-number-reset (java.util.Date.)
    :user/failed-phone-number-reset-count 0}
   [:db/retract (:db/id user) :user/new-phone-number]
   [:db/retract (:db/id user) :user/phone-number-reset-code]])

(defn- update-user-with-phone-number-transaction [user]
  [[:db/retract (:db/id user) :user/phone-number]
   [:db/retract (:db/id user) :user/username]])

(defn claim-phone-number-transaction [claiming-user user-with-phone-number]
  (concat
   (update-claiming-user-transaction claiming-user)
   (update-user-with-phone-number-transaction user-with-phone-number)))

(defn login-transaction [user]
  [{:user/last-login (java.util.Date.)
    :user/failed-logins-count 0
    :app/uuid (:app/uuid user)}])

(defn update-last-confirmed-transaction [user]
  [{:user/last-confirmation (java.util.Date.)
    :app/uuid (:app/uuid user)}])

(defn update-date-transaction [user field]
  [{field (java.util.Date.)
    :app/uuid (:app/uuid user)}])

(defn update-last-reminder-transaction [user]
  [{:user/last-reminder (java.util.Date.)
    :app/uuid (:app/uuid user)}])

(defn update-last-reset-transaction [user]
  [{:user/last-password-reset (java.util.Date.)
    :app/uuid (:app/uuid user)}])

(defn update-last-phone-number-reset-email-transaction [user]
  [{:user/last-phone-number-reset-email (java.util.Date.)
    :app/uuid (:app/uuid user)}])

(defn phone-password-reset-transaction [user]
  [{:user/last-password-reset (java.util.Date.)
    :user/failed-password-reset-count 0
    :app/uuid (:app/uuid user)}])

(defn failed-login-transaction [user]
  (let [failed-count (or (:user/failed-logins-count user) 0)]
    [{:app/uuid (:app/uuid user)
      :user/failed-logins-count (+ 1 failed-count)
      :user/last-failed-login (java.util.Date.)}]))

(defn failed-confirmation-code-transaction [user]
  (let [failed-count (or (:user/failed-confirmations-count user) 0)]
    [{:app/uuid (:app/uuid user)
      :user/failed-confirmations-count (+ 1 failed-count)
      :user/last-failed-confirmation (java.util.Date.)}]))

(defn failed-password-reset-code-transaction [user]
  (let [failed-count (or (:user/failed-password-reset-count user) 0)]
    [{:app/uuid (:app/uuid user)
      :user/failed-password-reset-count (+ 1 failed-count)
      :user/last-failed-password-reset (java.util.Date.)}]))

(defn failed-phone-number-change-code-transaction [user]
  (let [failed-count (or (:user/failed-phone-number-change-count user) 0)]
    [{:app/uuid (:app/uuid user)
      :user/failed-phone-number-change-count (+ 1 failed-count)
      :user/last-failed-phone-number-change (java.util.Date.)}]))

(defn failed-phone-number-claim-code-transaction [user]
  (let [failed-count (or (:user/failed-phone-number-claim-count user) 0)]
    [{:app/uuid (:app/uuid user)
      :user/failed-phone-number-claim-count (+ 1 failed-count)
      :user/last-failed-phone-number-claim (java.util.Date.)}]))

(defn failed-phone-number-reset-code-transaction [user]
  (let [failed-count (or (:user/failed-phone-number-reset-count user) 0)]
    [{:app/uuid (:app/uuid user)
      :user/failed-phone-number-reset-count (+ 1 failed-count)
      :user/last-failed-phone-number-reset (java.util.Date.)}]))

(defn update-email-transaction [user email]
  [[:db/cas (:db/id user) :user/email (:user/email user) email]
   [:db/add (:db/id user) :user/last-email-update (java.util.Date.)]])

(defn update-new-phone-number [user phone-number]
  [[:db/add (:db/id user) :user/new-phone-number phone-number]])

(defn update-id-transaction [user kw id]
  [{:app/uuid (:app/uuid user)
    kw id}])

(defn get-user-role [config snapshot user]
  (some->> user
           :user/role
           (db/solve-enum config snapshot) name))

(defn confirm-transaction [user]
  (when-not (:user/confirmed user)
    [[:db/add (:db/id user) :user/confirmed true]]))

(defn get-user-base-path [user]
  (let [user-clinic-base-path (some-> user
                                      :user/additional-data
                                      (read-str :key-fn keyword)
                                      :domain)]
    user-clinic-base-path))

(defn login-success-response [config snapshot user session-id]
  (let [additional-data (some-> user :user/additional-data read-str)
        access-token (u/generate-token config user session-id)]
    {:success true
     :access-token access-token
     :internal-user-id (:app/uuid user)
     :email (:user/email user)
     :phone-number (:user/phone-number user)
     :confirmed (-> user :user/confirmed boolean)
     :username (:user/username user)
     :role (get-user-role config snapshot user)
     :additional-data additional-data}))
