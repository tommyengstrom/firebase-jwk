{-# LANGUAGE DataKinds #-}
{-# LANGUAGE LambdaCase #-}

module ApiSpec where

import Data.ByteString.Lazy qualified as BL
import Data.Text.Encoding (encodeUtf8)
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

spec :: Spec
spec = describe "something" $
    it "works" $ do
        False `shouldBe` True
