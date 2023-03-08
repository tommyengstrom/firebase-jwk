{-# LANGUAGE OverloadedStrings #-}

module Firebase.JWK.Store (
    getCurrentKeys,
    createKeyStore,
    keyStoreKeys,
    KeyStore,
) where

import Control.Concurrent.MVar
import Control.Lens
import Control.Monad.Except
import Crypto.JWT
import Data.ByteString.Char8 (unpack)
import Data.ByteString.Lazy (ByteString)
import Data.Time
import Data.Time.Format
import Firebase.JWK.Convert
import Firebase.JWK.Store.Internal
import Firebase.JWK.Types
import Network.Wreq
import Network.Wreq.Session (Session, newAPISession)
import qualified Network.Wreq.Session as Session

-- | Get the current keys without using a store.
getCurrentKeys :: IO [JWK]
getCurrentKeys = googleKeysToJWKs . view responseBody <$> (asJSON =<< get firebaseKeysUrl)

-- * Exported API

-- --------------

{- | Get the current keys and put them into the store.
 | This function expects the store to be empty.
-}
fillKeyStore :: KeyStore -> IO ()
fillKeyStore = fillKeyStoreLogic defaultKeyStoreLogic

-- | Create a KeyStore. Will request the current keys before returning.
createKeyStore :: IO KeyStore
createKeyStore = createKeyStoreLogic defaultKeyStoreLogic

-- | Get the current keys. If they are expired get new ones, if not get from cache.
keyStoreKeys :: KeyStore -> IO [JWK]
keyStoreKeys = keyStoreKeysLogic defaultKeyStoreLogic

sampleToken :: ByteString
sampleToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImY4NzZiNzIxNDAwYmZhZmEyOWQ0MTFmZTYwODE2YmRhZWMyM2IzODIiLCJ0eXAiOiJKV1QifQ.eyJuYW1lIjoiVG9tbXkgRW5nc3Ryb20iLCJpc3MiOiJodHRwczovL3NlY3VyZXRva2VuLmdvb2dsZS5jb20vc3dlcS0zNzgxMDUiLCJhdWQiOiJzd2VxLTM3ODEwNSIsImF1dGhfdGltZSI6MTY3ODA5NDM5OSwidXNlcl9pZCI6InZYS3daeFFQWmxRQm1rM2VBdTYxWFowaEppczEiLCJzdWIiOiJ2WEt3WnhRUFpsUUJtazNlQXU2MVhaMGhKaXMxIiwiaWF0IjoxNjc4MDk0Mzk5LCJleHAiOjE2NzgwOTc5OTksImVtYWlsIjoidG9tbXlAdG9tbXllbmdzdHJvbS5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiZmlyZWJhc2UiOnsiaWRlbnRpdGllcyI6eyJlbWFpbCI6WyJ0b21teUB0b21teWVuZ3N0cm9tLmNvbSJdfSwic2lnbl9pbl9wcm92aWRlciI6InBhc3N3b3JkIn19.Zqq1gC5bNVoohWR5m5eCEKgXtkLws0X_XZ5vmbpJAgxXcjVyRiFFRv3kS7TOw4UsfUo3a-YiCO5XhKB5oSOflSjCNhwkVemwEs4xHjeyutyjD3do2IUYt1b3YlrcXnXb6uq9aSP5WnhZxSuu78oypaUK_6-OqzHcKyFGyhhwDXzbkOMw0Sq0DPXHxx2yQeqX3imo7kdJpqdYkIihn0tRKFVv5mCCiOSX6Eul8rOLKOXSU7LTu4qyqPfqgKVNV5EUkdZY5yJMb8GLOvlvLW8iIyTsqJleTE3fl9ye8TY4fPgZaMkiJD4mYmgH-2hJ6uZywbcKJ4SmWIOqolylckKFbA"

verifyFirebaseJWT :: ByteString -> IO (Either JWTError ClaimsSet)
verifyFirebaseJWT tok = runExceptT $ do
    jwt <- decodeCompact tok
    jwkSet <- liftIO $ JWKSet <$> getCurrentKeys
    let config = defaultJWTValidationSettings (== "https://securetoken.google.com/sweq-378105")
    verifyClaims config jwkSet jwt
