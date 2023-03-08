module Servant.Auth.Firebase where

import Control.Monad.Except
import Control.Monad.IO.Class
import Control.Monad.Time (MonadTime (..))
import Crypto.JWT qualified as JWT
import Data.ByteString qualified as BS
import Data.ByteString.Lazy qualified as BL
import Data.Kind
import Data.Maybe
import Data.Text (Text)
import Data.Text qualified as T
import Firebase.JWK.Store qualified as FB
import GHC.Generics
import Network.HTTP.Types
import Network.Wai qualified as Wai
import Servant
import Servant.Auth
import Servant.Server.Internal.Delayed (Delayed (..), addAuthCheck)
import Servant.Server.Internal.DelayedIO (DelayedIO, withRequest)
import Servant.Server.Internal.Router (Router)
import Prelude

verifyFirebaseJWT
    :: (MonadTime m, MonadIO m)
    => BL.ByteString
    -> m (Either JWT.JWTError JWT.ClaimsSet)
verifyFirebaseJWT tok = runExceptT $ do
    jwt <- JWT.decodeCompact tok
    jwkSet <- liftIO $ JWT.JWKSet <$> FB.getCurrentKeys
    let config = JWT.defaultJWTValidationSettings (== "sweq-378105")
    JWT.verifyClaims config jwkSet jwt

data FirebaseSettings = FirebaseSettings
    { jwkSet :: JWT.JWKSet
    , validationSettings :: JWT.JWTValidationSettings
    }
    deriving (Generic)

type FirebaseProjectId = JWT.StringOrURI

mkFirebaseVerificationSettings :: MonadIO m => FirebaseProjectId -> m FirebaseSettings
mkFirebaseVerificationSettings projectId = do
    jwkSet <- JWT.JWKSet <$> liftIO FB.getCurrentKeys
    pure
        FirebaseSettings
            { jwkSet = jwkSet
            , validationSettings = JWT.defaultJWTValidationSettings (== projectId)
            }

data FirebaseAuth
data FirebaseJWT

data FirebaseUser = FirebaseUser
    { uid :: String
    }
    deriving (Show, Eq, Generic)

data FirebaseAuthResult
    = AuthenticatedFB FirebaseUser
    | UnauthorizedFB Text

instance
    ( HasServer api ctx
    , HasContextEntry ctx FirebaseSettings
    )
    => HasServer (FirebaseAuth :> api) ctx
    where
    type ServerT (FirebaseAuth :> api) m = FirebaseAuthResult -> ServerT api m

    hoistServerWithContext
        :: forall (m :: Type -> Type) (n :: Type -> Type)
         . Proxy (FirebaseAuth :> api)
        -> Proxy ctx
        -> (forall x. m x -> n x)
        -> (FirebaseAuthResult -> ServerT api m)
        -> FirebaseAuthResult
        -> ServerT api n
    hoistServerWithContext _ pc nt s = hoistServerWithContext (Proxy @api) pc nt . s

    route
        :: forall env
         . Proxy (FirebaseAuth :> api)
        -> Context ctx
        -> Delayed env (FirebaseAuthResult -> Server api)
        -> Router env
    route _ ctx subserver =
        route
            (Proxy @api)
            ctx
            (subserver `addAuthCheck` authCheck)
      where
        authCheck :: DelayedIO FirebaseAuthResult
        authCheck = withRequest $ \req -> liftIO $ do
            case getAuthorizationToken $ Wai.requestHeaders req of
                Nothing -> pure $ UnauthorizedFB "No bearer token found in `Authorization` header"
                Just token -> do
                    user <- checkFirebaseToken (getContextEntry ctx) token
                    pure user

checkFirebaseToken
    :: MonadTime m
    => FirebaseSettings
    -> BS.ByteString
    -> m FirebaseAuthResult
checkFirebaseToken settings tok = do
    verificationResult <- runExceptT $ do
        jwt <- JWT.decodeCompact $ BL.fromStrict tok
        JWT.verifyClaims (validationSettings settings) (jwkSet settings) jwt
    pure $ case verificationResult of
        Right claims -> AuthenticatedFB (FirebaseUser $ show claims)
        Left err' -> case err' of
            JWT.JWSError err -> UnauthorizedFB . T.pack $ show err
            JWT.JWTClaimsSetDecodeError err ->
                UnauthorizedFB $ "JWTClaimsSetDecodeError: " <> T.pack err
            JWT.JWTExpired -> UnauthorizedFB "Token has expired"
            JWT.JWTNotYetValid -> UnauthorizedFB "NotYetValid"
            JWT.JWTNotInIssuer -> UnauthorizedFB "NotInIssuer"
            JWT.JWTNotInAudience -> UnauthorizedFB "NotInAudience"
            JWT.JWTIssuedAtFuture -> UnauthorizedFB "IssuedAtFuture"

getAuthorizationToken :: RequestHeaders -> Maybe BS.ByteString
getAuthorizationToken headers = do
    rawAuthHeaderValue <- listToMaybe $ do
        (headerName, v) <- headers
        guard $ headerName == "authorization"
        pure v
    BS.stripPrefix "Bearer " rawAuthHeaderValue
