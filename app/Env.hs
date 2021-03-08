{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE RecordWildCards #-}

-- |
module Env
  ( Env,
    auth,
    getEnv,
  )
where

import Data.Text (Text)
import qualified Data.Text as T
import GHC.Generics (Generic)
-- import qualified Godaddy
import qualified Keycloak
import qualified Servant.Client as SC
import qualified System.Envy as Envy

data Env = Env
  { keycloakAuthUsername :: Maybe Text,
    keycloakAuthPassword :: Maybe Text,
    keycloakAuthClientid :: Maybe ClientID
    -- godaddyCustomEndpoint :: Maybe Endpoint,
    -- godaddyTestEndpoint :: Bool
  }
  deriving (Generic)

instance Envy.FromEnv Env

newtype Endpoint = Endpoint {unEndpoint :: SC.BaseUrl}

instance Envy.Var Endpoint where
  toVar = SC.showBaseUrl . unEndpoint
  fromVar = fmap Endpoint . SC.parseBaseUrl

newtype ClientID = ClientID {unClientID :: Text}

instance Envy.Var ClientID where
  toVar = T.unpack . unClientID
  fromVar = Just . ClientID . T.pack

getEnv :: IO Env
getEnv = Envy.decodeWithDefaults (Env Nothing Nothing Nothing)

-- endpoint :: Env -> SC.BaseUrl
-- endpoint env = case (godaddyTestEndpoint env, godaddyCustomEndpoint env) of
--   (False, Just custom) -> Env.unEndpoint custom
--   (True, _) -> Godaddy.testBaseUrl
--   _ -> Godaddy.defaultBaseUrl

auth :: Env -> Maybe Keycloak.AuthCredentials
auth Env {..} =
  Keycloak.PasswordAuth
    <$> keycloakAuthUsername
    <*> keycloakAuthPassword
    <*> fmap (Keycloak.ClientID . unClientID) keycloakAuthClientid
