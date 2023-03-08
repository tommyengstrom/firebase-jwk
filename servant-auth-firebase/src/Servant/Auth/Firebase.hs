{-# HLINT ignore "Use newtype instead of data" #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}

module Servant.Auth.Firebase where

import Control.Monad.IO.Class
import Data.ByteString qualified as BS
import Data.Kind
import Data.Maybe
import Data.Text (Text)
import Data.Text qualified as T
import GHC.Generics
import Network.HTTP.Types
import Network.Wai qualified as Wai
import Servant
import Servant.Auth
import Servant.Server.Internal.Delayed (Delayed (..), addAuthCheck)
import Servant.Server.Internal.DelayedIO (DelayedIO, withRequest)
import Servant.Server.Internal.Router (Router)
import Prelude

-----------

import Control.Monad.Except
import Crypto.JWT qualified as JWT
import Data.ByteString.Lazy qualified as BL

import Firebase.JWK.Store qualified as FB

token :: BL.ByteString
token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjU4ODI0YTI2ZjFlY2Q1NjEyN2U4OWY1YzkwYTg4MDYxMTJhYmU5OWMiLCJ0eXAiOiJKV1QifQ.eyJuYW1lIjoiVG9tbXkgRW5nc3Ryb20iLCJpc3MiOiJodHRwczovL3NlY3VyZXRva2VuLmdvb2dsZS5jb20vc3dlcS0zNzgxMDUiLCJhdWQiOiJzd2VxLTM3ODEwNSIsImF1dGhfdGltZSI6MTY3ODI1OTYwNCwidXNlcl9pZCI6InZYS3daeFFQWmxRQm1rM2VBdTYxWFowaEppczEiLCJzdWIiOiJ2WEt3WnhRUFpsUUJtazNlQXU2MVhaMGhKaXMxIiwiaWF0IjoxNjc4MjU5NjA0LCJleHAiOjE2NzgyNjMyMDQsImVtYWlsIjoidG9tbXlAdG9tbXllbmdzdHJvbS5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiZmlyZWJhc2UiOnsiaWRlbnRpdGllcyI6eyJlbWFpbCI6WyJ0b21teUB0b21teWVuZ3N0cm9tLmNvbSJdfSwic2lnbl9pbl9wcm92aWRlciI6InBhc3N3b3JkIn19.WRJLcGMH9h9AXYNg2po8A92SzviNlem1sVjxEI6GH8UDyQY2UpzH1A5p6qsVkTDhY_DyePifO1cmPROgBQWvZPKG9wT-fnnf12urqidAlegAY9QDsnpc3uKaNtFkW-NKaCjEFvlLmrVv23KDJWPdGAIanc0PdQmt3GzHvxhmBD_YjEhizhiM9Zw7rXhRFw_EJkSlVZF4deVXVigNWBpp-mwfx65hF1xpusqy4zLwhWlZAbuVVPAKGe1jFObBiIG1ahu1ekcMrxCuL_dFQvMydH_jSak76Dh8rd7oq2gYi9wEN5CVuuSskE98QNQgR7_byyC2utXEcqPg-K10ninBWw"

verifyFirebaseJWT :: BL.ByteString -> IO (Either JWT.JWTError JWT.ClaimsSet)
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

mkFirebaseVerificationSettings :: FirebaseProjectId -> IO FirebaseSettings
mkFirebaseVerificationSettings projectId = do
    jwkSet <- JWT.JWKSet <$> FB.getCurrentKeys
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

checkFirebaseToken :: FirebaseSettings -> BS.ByteString -> IO FirebaseAuthResult
checkFirebaseToken settings tok = do
    verificationResult <- runExceptT $ do
        jwt <- JWT.decodeCompact $ BL.fromStrict tok
        JWT.verifyClaims (validationSettings settings) (jwkSet settings) jwt
    pure $ case verificationResult of
        Right claims -> AuthenticatedFB (FirebaseUser $ show claims)
        Left err' -> case err' of
            JWT.JWSError err -> UnauthorizedFB . T.pack $ show err
            JWT.JWTClaimsSetDecodeError err -> UnauthorizedFB $ "JWTClaimsSetDecodeError: " <> T.pack err
            JWT.JWTExpired -> UnauthorizedFB "Expired"
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

--   route
--       (Proxy @api)
--       ctx
--       (fmap undefined subserver `addAuthCheck` authCheck)
-- where
--   authCheck = undefined

-- addAuthCheck ::
--   forall env a b.
--   Servant.Server.Internal.Delayed.Delayed env (a -> b)
--   -> Servant.Server.Internal.DelayedIO.DelayedIO a
--   -> Servant.Server.Internal.Delayed.Delayed env b

-- instance ( n ~ 'S ('S 'Z)
--          , HasServer (AddSetCookiesApi n api) ctx, AreAuths auths ctx v
--          , HasServer api ctx -- this constraint is needed to implement hoistServer
--          , AddSetCookies n (ServerT api Handler) (ServerT (AddSetCookiesApi n api) Handler)
--          , ToJWT v
--          , HasContextEntry ctx CookieSettings
--          , HasContextEntry ctx JWTSettings
--          ) => HasServer (Auth auths v :> api) ctx where
--   type ServerT (Auth auths v :> api) m = AuthResult v -> ServerT api m
