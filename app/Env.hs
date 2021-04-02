{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE RecordWildCards #-}

-- |
module Env
  ( Env,
    auth,
    Endpoint,
    endpoint,
    asBaseUrl,
    getEnv,
  )
where

import Data.Text (Text)
import qualified Data.Text as T
import GHC.Generics (Generic)
import qualified Keycloak
import qualified Servant.Client as SC
import qualified System.Envy as Envy

data Env = Env
  { keycloakAuthUsername :: Maybe Text,
    keycloakAuthPassword :: Maybe Text,
    keycloakAuthClientid :: Maybe ClientID,
    keycloakEndpoint :: Maybe Endpoint
  }
  deriving (Generic)

instance Envy.FromEnv Env

newtype Endpoint = Endpoint {unEndpoint :: SC.BaseUrl}
  deriving (Show)

instance Envy.Var Endpoint where
  toVar = SC.showBaseUrl . unEndpoint
  fromVar = fmap Endpoint . SC.parseBaseUrl

newtype ClientID = ClientID {unClientID :: Text}

instance Envy.Var ClientID where
  toVar = T.unpack . unClientID
  fromVar = Just . ClientID . T.pack

getEnv :: IO Env
getEnv = Envy.decodeWithDefaults (Env Nothing Nothing Nothing Nothing)

endpoint :: Env -> Maybe Endpoint
endpoint = keycloakEndpoint

asBaseUrl :: Endpoint -> SC.BaseUrl
asBaseUrl = unEndpoint

auth :: Env -> Maybe Keycloak.AuthCredentials
auth Env {..} =
  Keycloak.PasswordAuth
    <$> keycloakAuthUsername
    <*> keycloakAuthPassword
    <*> fmap (Keycloak.ClientID . unClientID) keycloakAuthClientid
