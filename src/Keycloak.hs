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
    Realm (..),
    ProtocolName (..),
    KeycloakClient (..),
    mkClient,
    authenticateQuery,
    clientQueries,
    ClientInfo (..),
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

authenticateQuery :: KeycloakClient -> ProtocolName -> SC.ClientM AuthToken
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

clientQueries :: KeycloakClient -> AuthToken -> Rest.APIQueries ClientID ClientInfo
clientQueries kc authToken = do
  let APIQueries {..} = mkApiQueries
      AuthenticatedAPIQueries {..} = mkAuthenticatedAPI authToken
  mkAdminAPI $ realm kc

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
    -- ciProtocolMappers :: Maybe [ProtocolMapperRepresentation]
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

data ProtocolName = OpenidConnect

instance S.ToHttpApiData ProtocolName where
  toUrlPiece OpenidConnect = "openid-connect"

instance ToJSON ProtocolName where
  toJSON OpenidConnect = "openid-connect"

data Protocol = Protocol
  { pName :: Text,
    pProtocol :: ProtocolName,
    pProtocolMapper :: Text,
    pConsentRequired :: Bool,
    pConfig :: ProtocolConfig
  }
  deriving (Generic)

instance ToJSON Protocol where
  toJSON =
    Aeson.genericToJSON
      ( Aeson.defaultOptions
          { Aeson.fieldLabelModifier = removePrefix "c"
          }
      )

data ProtocolConfig = ProtocolConfig
  { p_included_client_audience :: Text,
    p_id_token_claim :: Bool,
    p_access_token_claim :: Bool
  }
  deriving (Generic)

instance ToJSON ProtocolConfig where
  toJSON =
    Aeson.genericToJSON
      ( Aeson.defaultOptions
          { Aeson.fieldLabelModifier = replaceChar '_' '.' . removePrefix "p_"
          }
      )

type API =
  AuthAPI
    :<|> S.Header "Authorization" AuthToken
    :> AdminAPI

type AuthAPI =
  "realms"
    :> S.Capture "realm" Realm
    :> "protocol"
    :> S.Capture "protocolName" ProtocolName
    :> "token"
    :> S.ReqBody '[S.FormUrlEncoded] TokenRequest
    :> S.Post '[S.JSON] AuthToken

data APIQueries = APIQueries
  { requestAuthToken :: Realm -> ProtocolName -> TokenRequest -> SC.ClientM AuthToken,
    mkAuthenticatedAPI :: AuthToken -> AuthenticatedAPIQueries
  }

type AdminAPI =
  "admin"
    :> "realms"
    :> S.Capture "realm" Realm
    :> "clients"
    :> ( Rest.API (S.QueryParam "clientId" ClientID) ClientInfo
    -- :<|> S.Capture "resourceId" ResourceID
    --   :> "protocol-mappers"
    --   :> "models"
    --   :> S.ReqBody '[S.JSON] Protocol
    --   :> S.Post '[S.JSON] S.NoContent
       )

newtype AuthenticatedAPIQueries = AuthenticatedAPIQueries
  { mkAdminAPI :: Realm -> Rest.APIQueries ClientID ClientInfo
  }

mkApiQueries :: APIQueries
mkApiQueries = APIQueries {..}
  where
    client = SC.client (Proxy :: Proxy API)

    requestAuthToken :<|> authenticatedAPI = client

    mkAuthenticatedAPI authToken = AuthenticatedAPIQueries {..}
      where
        adminAPI = authenticatedAPI (Just authToken)

        mkAdminAPI realm = Rest.mkAPIQueries (adminAPI realm)

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
