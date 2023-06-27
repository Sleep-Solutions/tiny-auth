(defproject tiny-auth "0.1.23"
  :description "Authentication/authorization module."
  :url "https://github.com/spinneyio/tiny-auth"
  :dependencies [[org.clojure/clojure "1.10.3"]
                 [org.clojure/data.json "1.0.0"]
                 [org.clojure/data.codec "0.1.1"]
                 [com.walmartlabs/cond-let "1.0.0"]
                 [buddy "2.0.0"]
                 [failjure "2.2.0"]
                 [clj-http "3.12.3"]
                 [clj-time "0.15.2"]
                 [metosin/ring-http-response "0.9.3"]
                 [io.randomseed/phone-number "8.12.28-1"]
                 [prismatic/schema "1.1.12"]]
  :main ^:skip-aot tiny-auth.core
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all
                       :jvm-opts ["-Dclojure.compiler.direct-linking=true"]}}
  :repositories [["github" {:url "https://maven.pkg.github.com/spinneyio/tiny-auth"
                            :username "private-token"
                            :password :env/GITHUB_TOKEN
                            :sign-releases false}]])
