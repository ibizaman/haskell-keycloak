{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeOperators #-}

-- |
module Keycloak
  ( ClientID (..),
    AuthCredentials (..),
    AuthToken,
    Realm (..),
    KeycloakClient (..),
    mkClient,
    authenticateQuery,
    clientQueries,
    Secret (..),
    secretQueries,
    ClientAPIQueries (getSecret),
    ClientInfo (..),
    ProtocolMapper (..),
    ProtocolName (..),
    ProtocolType (..),
    ProtocolConfig (..),
    protocolMapperQueries,
    Error (..),
    Status (..),
    KeycloakError (..),
    parseError,
  )
where

-- https://github.com/keycloak/keycloak-documentation/blob/master/server_admin/topics/admin-cli.adoc

import Data.Aeson
  ( FromJSON (..),
    ToJSON (..),
  )
import qualified Data.Aeson as Aeson
import Data.Char (isUpper, toLower)
import Data.Map.Strict (Map)
import Data.Proxy (Proxy (Proxy))
import Data.Text (Text)
import qualified Data.Text as T
import GHC.Generics (Generic)
import qualified Network.HTTP.Types as HTTPTypes
import qualified Rest
import Servant ((:<|>) (..), (:>))
import qualified Servant as S
import qualified Servant.Client as SC
import qualified Web.FormUrlEncoded as Web

newtype ClientID = ClientID {unClientID :: Text}

instance S.ToHttpApiData ClientID where
  toUrlPiece = unClientID

data AuthCredentials = PasswordAuth
  { username :: Text,
    password :: Text,
    clientId :: ClientID
  }

newtype Realm = Realm Text

instance S.ToHttpApiData Realm where
  toUrlPiece (Realm realm) = realm

data KeycloakClient = KeycloakClient
  { apiAuth :: AuthCredentials,
    realm :: Realm,
    token :: Maybe AuthToken
  }

mkClient :: AuthCredentials -> Realm -> KeycloakClient
mkClient apiAuth realm =
  KeycloakClient
    { apiAuth = apiAuth,
      realm = realm,
      token = Nothing
    }

authenticateQuery :: KeycloakClient -> ProtocolType -> SC.ClientM AuthToken
authenticateQuery kc pn = do
  let APIQueries {..} = mkApiQueries
  requestAuthToken (realm kc) pn (mkTokenRequest $ apiAuth kc)
  where
    mkTokenRequest PasswordAuth {..} =
      TokenRequest
        { trGrantType = "password",
          trUsername = username,
          trPassword = password,
          trClientId = unClientID clientId
        }

clientQueries :: KeycloakClient -> AuthToken -> Rest.APIQueries Text ClientInfo
clientQueries kc authToken = do
  let APIQueries {..} = mkApiQueries
      RealmAPIQueries {..} = mkRealmAPI authToken
      ClientAPIQueries {..} = mkClientsAPI $ realm kc
  mkAdminAPI

secretQueries :: KeycloakClient -> AuthToken -> ClientAPIQueries
secretQueries kc authToken = do
  let APIQueries {..} = mkApiQueries
      RealmAPIQueries {..} = mkRealmAPI authToken
  mkClientsAPI $ realm kc

protocolMapperQueries :: KeycloakClient -> AuthToken -> Rest.ResourceID -> Rest.APIQueries ProtocolName ProtocolMapper
protocolMapperQueries kc authToken clientId = do
  let APIQueries {..} = mkApiQueries
      RealmAPIQueries {..} = mkRealmAPI authToken
      ClientAPIQueries {..} = mkClientsAPI $ realm kc
  mkProtocolMappersAPI clientId

data AuthToken = AuthToken
  { accessToken :: Text,
    tokenType :: Text,
    not_before_policy :: Int,
    sessionState :: Text,
    scope :: Text,
    expiresIn :: Int,
    refreshToken :: Text,
    refreshExpiresIn :: Int
  }
  deriving (Show, Generic)

instance FromJSON AuthToken where
  parseJSON =
    Aeson.genericParseJSON
      ( Aeson.defaultOptions
          { Aeson.fieldLabelModifier = camelCaseToSnakeCase . replaceChar '_' '-'
          }
      )

instance S.ToHttpApiData AuthToken where
  toUrlPiece AuthToken {accessToken, tokenType} = tokenType <> " " <> accessToken

data TokenRequest = TokenRequest
  { trGrantType :: Text,
    trUsername :: Text,
    trPassword :: Text,
    trClientId :: Text
  }
  deriving (Generic)

instance Web.ToForm TokenRequest where
  toForm =
    Web.genericToForm
      Web.FormOptions
        { fieldLabelModifier = drop (length ("tr_" :: String)) . camelCaseToSnakeCase
        }

data ClientInfo = ClientInfo
  -- Commented out fields are TODO
  { ciClientId :: Text,
    ciAccess :: Maybe (Map String Bool),
    ciAdminUrl :: Maybe Text,
    ciAlwaysDisplayInConsole :: Maybe Bool,
    ciAttributes :: Maybe (Map String String),
    ciAuthenticationFlowBindingOverrides :: Maybe (Map String String),
    ciAuthorizationServicesEnabled :: Maybe Bool,
    -- ciAuthorizationSettings :: ResourceServerRepresentation,
    ciBaseUrl :: Maybe Text,
    ciBearerOnly :: Maybe Bool,
    ciClientAuthenticatorType :: Maybe Text,
    ciConsentRequired :: Maybe Bool,
    ciDefaultClientScopes :: Maybe [Text],
    ciDefaultRoles :: Maybe [Text],
    ciDescription :: Maybe Text,
    ciDirectAccessGrantsEnabled :: Maybe Bool,
    ciEnabled :: Maybe Bool,
    ciFrontchannelLogout :: Maybe Bool,
    ciFullScopeAllowed :: Maybe Bool,
    ciImplicitFlowEnabled :: Maybe Bool,
    ciName :: Maybe Text,
    ciNodeReRegistrationTimeout :: Maybe Int,
    ciNotBefore :: Maybe Int,
    ciOptionalClientScopes :: Maybe [Text],
    ciOrigin :: Maybe Text,
    ciProtocol :: Maybe Text,
    ciPublicClient :: Maybe Bool,
    ciRedirectUris :: Maybe [Text],
    ciRegisteredNodes :: Maybe (Map String String),
    ciRegistrationAccessToken :: Maybe Text,
    ciRootUrl :: Maybe Text,
    ciSecret :: Maybe Text,
    ciServiceAccountsEnabled :: Maybe Bool,
    ciStandardFlowEnabled :: Maybe Bool,
    ciSurrogateAuthRequired :: Maybe Bool,
    ciWebOrigins :: Maybe [Text]
  }
  deriving (Generic)

instance ToJSON ClientInfo where
  toJSON =
    Aeson.genericToJSON
      ( Aeson.defaultOptions
          { Aeson.fieldLabelModifier = removePrefix "ci",
            Aeson.omitNothingFields = True
          }
      )

instance FromJSON ClientInfo where
  parseJSON =
    Aeson.genericParseJSON
      ( Aeson.defaultOptions
          { Aeson.fieldLabelModifier = removePrefix "ci"
          }
      )

data ProtocolType = OpenidConnect
  deriving (Generic)

instance ToJSON ProtocolType where
  toJSON OpenidConnect = "openid-connect"

instance FromJSON ProtocolType where
  parseJSON =
    Aeson.withText
      "protocolName"
      ( \case
          "openid-connect" -> pure OpenidConnect
          t -> fail $ "Unkown protocol " <> T.unpack t
      )

instance S.ToHttpApiData ProtocolType where
  toUrlPiece OpenidConnect = "openid-connect"

newtype ProtocolName = ProtocolName Text
  deriving (Eq, Generic)

instance Show ProtocolName where
  show (ProtocolName p) = T.unpack p

instance ToJSON ProtocolName

instance FromJSON ProtocolName

instance S.ToHttpApiData ProtocolName where
  toUrlPiece (ProtocolName n) = n

data ProtocolMapper = ProtocolMapper
  { pName :: ProtocolName,
    pProtocol :: ProtocolType,
    pProtocolMapper :: Text,
    pConsentRequired :: Bool,
    pConfig :: ProtocolConfig
  }
  deriving (Generic)

instance ToJSON ProtocolMapper where
  toJSON =
    Aeson.genericToJSON
      ( Aeson.defaultOptions
          { Aeson.fieldLabelModifier = removePrefix "p"
          }
      )

instance FromJSON ProtocolMapper where
  parseJSON =
    Aeson.genericParseJSON
      ( Aeson.defaultOptions
          { Aeson.fieldLabelModifier = removePrefix "p"
          }
      )

data ProtocolConfig = ProtocolConfig
  { pIncluded_client_audience :: Maybe Text,
    pId_token_claim :: Maybe Text,
    pClaim_name :: Maybe Text,
    pJsonType_label :: Maybe Text,
    pAccess_token_claim :: Maybe Text
  }
  deriving (Generic)

instance ToJSON ProtocolConfig where
  toJSON =
    Aeson.genericToJSON
      ( Aeson.defaultOptions
          { Aeson.fieldLabelModifier = replaceChar '_' '.' . removePrefix "p"
          }
      )

instance FromJSON ProtocolConfig where
  parseJSON =
    Aeson.genericParseJSON
      ( Aeson.defaultOptions
          { Aeson.fieldLabelModifier = replaceChar '_' '.' . removePrefix "p"
          }
      )

data ClientSecret = ClientSecret
  { secretType :: Text,
    secretValue :: Secret
  }
  deriving (Generic)

instance ToJSON ClientSecret where
  toJSON =
    Aeson.genericToJSON
      ( Aeson.defaultOptions
          { Aeson.fieldLabelModifier = removePrefix "secret",
            Aeson.omitNothingFields = True
          }
      )

instance FromJSON ClientSecret where
  parseJSON =
    Aeson.genericParseJSON
      ( Aeson.defaultOptions
          { Aeson.fieldLabelModifier = removePrefix "secret"
          }
      )

newtype Secret = Secret Text
  deriving (Generic)

instance FromJSON Secret

instance ToJSON Secret

type API =
  AuthAPI
    :<|> S.Header "Authorization" AuthToken
    :> RealmAPI

data APIQueries = APIQueries
  { requestAuthToken :: Realm -> ProtocolType -> TokenRequest -> SC.ClientM AuthToken,
    mkRealmAPI :: AuthToken -> RealmAPIQueries
  }

type AuthAPI =
  "realms"
    :> S.Capture "realm" Realm
    :> "protocol"
    :> S.Capture "protocolType" ProtocolType
    :> "token"
    :> S.ReqBody '[S.FormUrlEncoded] TokenRequest
    :> S.Post '[S.JSON] AuthToken

type RealmAPI =
  "admin"
    :> "realms"
    :> S.Capture "realm" Realm
    :> "clients"
    :> ( ClientAPI
           :<|> SecretAPI
           :<|> ProtocolMapperAPI
       )

newtype RealmAPIQueries = RealmAPIQueries
  { mkClientsAPI :: Realm -> ClientAPIQueries
  }

type ClientAPI = Rest.API (S.QueryParam "clientId" Text) ClientInfo

type SecretAPI = S.Capture "resourceID" Rest.ResourceID :> "client-secret" :> S.Get '[S.JSON] ClientSecret

type ProtocolMapperAPI =
  S.Capture "resourceID" Rest.ResourceID :> "protocol-mappers"
    :> "models"
    :> Rest.API (S.QueryParam "name" ProtocolName) ProtocolMapper

data ClientAPIQueries = ClientAPIQueries
  { mkAdminAPI :: Rest.APIQueries Text ClientInfo,
    getSecret :: Rest.ResourceID -> SC.ClientM Secret,
    mkProtocolMappersAPI :: Rest.ResourceID -> Rest.APIQueries ProtocolName ProtocolMapper
  }

mkApiQueries :: APIQueries
mkApiQueries = APIQueries {..}
  where
    client = SC.client (Proxy :: Proxy API)

    requestAuthToken :<|> realmAPI = client

    mkRealmAPI authToken = RealmAPIQueries {..}
      where
        clientsAPI = realmAPI (Just authToken)

        mkClientsAPI realm = ClientAPIQueries {..}
          where
            adminAPI :<|> getSecret' :<|> protocolMappersAPI = clientsAPI realm

            mkAdminAPI = Rest.mkAPIQueries adminAPI ciClientId

            getSecret = fmap secretValue . getSecret'

            mkProtocolMappersAPI resourceID = Rest.mkAPIQueries (protocolMappersAPI resourceID) pName

-- | The error returned by Keycloak.
data Error
  = -- | An error returned by Keycloak.
    Error Status KeycloakError
  | -- | A request or response could not be decoded.
    DecodeError Status String String
  | -- | An unexpected error.
    OtherError Status String
  | -- | A network error.
    ConnectionError String
  deriving (Generic, Show)

instance FromJSON Error

-- | Status of an API call.
data Status = Status
  {statusCode :: Int, statusMessage :: String}
  deriving (Generic, Show)

instance FromJSON Status

-- | An error returned by Keycloak if a request is invalid. For
-- example if the credentials are incorrect.
data KeycloakError = KeycloakError
  { keycloakError :: Maybe String,
    keycloakErrorDescription :: Maybe String,
    keycloakErrorMessage :: Maybe String
  }
  deriving (Generic, Show)

instance FromJSON KeycloakError where
  parseJSON =
    Aeson.genericParseJSON
      ( Aeson.defaultOptions
          { Aeson.fieldLabelModifier = \case
              "keycloakError" -> "error"
              "keycloakErrorDescription" -> "error_description"
              "keycloakErrorMessage" -> "errorMessage"
              other -> other
          }
      )

-- | Parse JSON error coming from Keycloak.
parseError :: SC.ClientError -> Error
parseError clientError =
  case clientError of
    (SC.FailureResponse _ SC.Response {responseStatusCode = HTTPTypes.Status statusCode statusMessage, responseBody}) ->
      let p = Aeson.eitherDecode responseBody
          s = Status statusCode $ show statusMessage
       in either (DecodeError s $ show responseBody) (Error s) p
    SC.DecodeFailure failure SC.Response {responseStatusCode = HTTPTypes.Status statusCode statusMessage, responseBody} ->
      let s = Status statusCode $ show statusMessage
       in DecodeError s (T.unpack failure) $ show responseBody
    SC.UnsupportedContentType mediaType SC.Response {responseStatusCode = HTTPTypes.Status statusCode statusMessage, responseBody} ->
      let s = Status statusCode $ show statusMessage
       in OtherError s $ "unsupported media type: \"" <> show mediaType <> "\", reponse body: " <> show responseBody
    SC.InvalidContentTypeHeader SC.Response {responseStatusCode = HTTPTypes.Status statusCode statusMessage, responseBody} ->
      let s = Status statusCode $ show statusMessage
       in OtherError s $ show responseBody
    SC.ConnectionError exception ->
      ConnectionError $ show exception

removePrefix :: String -> String -> String
removePrefix prefix str = case drop (length prefix) str of
  (x : xs) -> toLower x : xs
  xs -> xs

replaceChar :: Char -> Char -> String -> String
replaceChar from to = map $ \c -> if c == from then to else c

camelCaseToSnakeCase :: String -> String
camelCaseToSnakeCase = foldr (\c str -> (if isUpper c then "_" ++ [toLower c] else [c]) ++ str) ""
