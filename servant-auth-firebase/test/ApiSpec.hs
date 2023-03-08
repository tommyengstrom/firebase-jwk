{-# LANGUAGE DataKinds #-}
{-# LANGUAGE LambdaCase #-}

module ApiSpec where

import Control.Monad.Reader
import Control.Monad.Time
import Crypto.JWT (JWTError (..))
import Data.ByteString.Lazy qualified as BL
import Data.Either
import Data.Text.Encoding (encodeUtf8)
import Data.Time
import Network.Wai.Handler.Warp qualified as Warp
import Servant
import Servant.Auth.Firebase
import Test.Hspec
import Prelude

type Api = Get '[JSON] String

type ProtectedApi = FirebaseAuth :> Api

server :: Server ProtectedApi
server = \case
    AuthenticatedFB user -> pure $ show user
    UnauthorizedFB t -> throwError (err401{errBody = BL.fromStrict $ encodeUtf8 t})

app :: FirebaseSettings -> Application
app authSettings = serveWithContext (Proxy @ProtectedApi) (authSettings :. EmptyContext) server

runApp :: IO ()
runApp = do
    authSettings <- mkFirebaseVerificationSettings "sweq-378105"
    Warp.run 7878 $ app authSettings

sampleToken :: BL.ByteString
sampleToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjU4ODI0YTI2ZjFlY2Q1NjEyN2U4OWY1YzkwYTg4MDYxMTJhYmU5OWMiLCJ0eXAiOiJKV1QifQ.eyJuYW1lIjoiVG9tbXkgRW5nc3Ryb20iLCJpc3MiOiJodHRwczovL3NlY3VyZXRva2VuLmdvb2dsZS5jb20vc3dlcS0zNzgxMDUiLCJhdWQiOiJzd2VxLTM3ODEwNSIsImF1dGhfdGltZSI6MTY3ODI1OTYwNCwidXNlcl9pZCI6InZYS3daeFFQWmxRQm1rM2VBdTYxWFowaEppczEiLCJzdWIiOiJ2WEt3WnhRUFpsUUJtazNlQXU2MVhaMGhKaXMxIiwiaWF0IjoxNjc4MjU5NjA0LCJleHAiOjE2NzgyNjMyMDQsImVtYWlsIjoidG9tbXlAdG9tbXllbmdzdHJvbS5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiZmlyZWJhc2UiOnsiaWRlbnRpdGllcyI6eyJlbWFpbCI6WyJ0b21teUB0b21teWVuZ3N0cm9tLmNvbSJdfSwic2lnbl9pbl9wcm92aWRlciI6InBhc3N3b3JkIn19.WRJLcGMH9h9AXYNg2po8A92SzviNlem1sVjxEI6GH8UDyQY2UpzH1A5p6qsVkTDhY_DyePifO1cmPROgBQWvZPKG9wT-fnnf12urqidAlegAY9QDsnpc3uKaNtFkW-NKaCjEFvlLmrVv23KDJWPdGAIanc0PdQmt3GzHvxhmBD_YjEhizhiM9Zw7rXhRFw_EJkSlVZF4deVXVigNWBpp-mwfx65hF1xpusqy4zLwhWlZAbuVVPAKGe1jFObBiIG1ahu1ekcMrxCuL_dFQvMydH_jSak76Dh8rd7oq2gYi9wEN5CVuuSskE98QNQgR7_byyC2utXEcqPg-K10ninBWw"

sampleTokenTime :: UTCTime
sampleTokenTime = UTCTime (fromGregorian 2023 3 8) (8 * 3600)

newtype TestMonad a = TestMonad (ReaderT UTCTime IO a)
    deriving newtype (Functor, Applicative, Monad, MonadIO)

instance MonadTime TestMonad where
    currentTime = TestMonad ask

runTestAt :: UTCTime -> TestMonad a -> IO a
runTestAt t (TestMonad m) = runReaderT m t

spec :: Spec
spec = describe "veirfyFirebaseJWT" $ do
    it "Accepts my old token at the right time" $ do
        r <- runTestAt sampleTokenTime $ verifyFirebaseJWT sampleToken
        r `shouldSatisfy` isRight
    it "My old token has now expired" $ do
        r <- verifyFirebaseJWT sampleToken
        r `shouldBe` Left JWTExpired
