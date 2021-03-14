{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}

-- |
module Keycloak
  ( ClientID (..),
    AuthCredentials (..),
    ResourceID (..),
    WithResourceID (..),
    Realm (..),
    ProtocolName (..),
    KeycloakClient (..),
    mkClient,
    authenticateQuery,
    ClientInfo (..),
    createClientQuery,
    listClientsQuery,
    showClientByResourceIDQuery,
    showClientByClientIDQuery,
    deleteClientByResourceIDQuery,
    deleteClientByClientIDQuery,
    Error (..),
    Status (..),
    KeycloakError (..),
    parseError,
  )
where

-- https://github.com/keycloak/keycloak-documentation/blob/master/server_admin/topics/admin-cli.adoc

import Data.Aeson
  ( FromJSON (..),
    KeyValue ((.=)),
    Options,
    ToJSON (..),
    (.!=),
    (.:),
    (.:?),
  )
import qualified Data.Aeson as Aeson
import Data.Aeson.Types (Parser)
import Data.Bifunctor (Bifunctor (bimap))
import Data.Char (isUpper, toLower)
import qualified Data.HashMap.Strict as HashMap
import Data.Monoid (Last (..))
import Data.Proxy (Proxy (Proxy))
import Data.Text (Text)
import qualified Data.Text as T
import GHC.Generics (Generic)
import Generic.Data (Generically (..))
import qualified Network.HTTP.Types as HTTPTypes
import Servant ((:<|>) (..), (:>))
import qualified Servant as S
import qualified Servant.Client as SC
import Utils (splitStringOnLastChar)
import qualified Utils
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
  let APIMethods {..} = mkApiMethods
  requestAuthToken (realm kc) pn (mkTokenRequest $ apiAuth kc)
  where
    mkTokenRequest PasswordAuth {..} =
      TokenRequest
        { trGrantType = "password",
          trUsername = username,
          trPassword = password,
          trClientId = unClientID clientId
        }

createClientQuery :: KeycloakClient -> AuthToken -> ClientInfo -> SC.ClientM (Either String ResourceID)
createClientQuery kc authToken clientInfo = do
  let APIMethods {..} = mkApiMethods
      AuthenticatedAPIMethods {..} = mkAuthenticatedAPI authToken
      AdminAPIMethods {..} = mkAdminAPI $ realm kc
  parseError' . S.lookupResponseHeader @"Location" <$> createClient clientInfo
  where
    parseError' :: S.ResponseHeader "Location" ResourceID -> Either String ResourceID
    parseError' (S.Header resourceID) = Right resourceID
    parseError' S.MissingHeader = Left "missing 'Location' header"
    parseError' (S.UndecodableHeader bs) = Left $ "error while decoding 'Location' header: " <> show bs

listClientsQuery :: KeycloakClient -> AuthToken -> SC.ClientM [WithResourceID ClientInfo]
listClientsQuery kc authToken = do
  let APIMethods {..} = mkApiMethods
      AuthenticatedAPIMethods {..} = mkAuthenticatedAPI authToken
      AdminAPIMethods {..} = mkAdminAPI $ realm kc
  listClients Nothing

showClientByResourceIDQuery :: KeycloakClient -> AuthToken -> ResourceID -> SC.ClientM (WithResourceID ClientInfo)
showClientByResourceIDQuery kc authToken resourceID = do
  let APIMethods {..} = mkApiMethods
      AuthenticatedAPIMethods {..} = mkAuthenticatedAPI authToken
      AdminAPIMethods {..} = mkAdminAPI $ realm kc
  getClient resourceID

showClientByClientIDQuery :: KeycloakClient -> AuthToken -> ClientID -> SC.ClientM (Maybe (WithResourceID ClientInfo))
showClientByClientIDQuery kc authToken clientID = do
  let APIMethods {..} = mkApiMethods
      AuthenticatedAPIMethods {..} = mkAuthenticatedAPI authToken
      AdminAPIMethods {..} = mkAdminAPI $ realm kc
  listClients (Just clientID) >>= \case
    [] -> return Nothing
    (x : _) -> return $ Just x

deleteClientByResourceIDQuery :: KeycloakClient -> AuthToken -> ResourceID -> SC.ClientM S.NoContent
deleteClientByResourceIDQuery kc authToken resourceID = do
  let APIMethods {..} = mkApiMethods
      AuthenticatedAPIMethods {..} = mkAuthenticatedAPI authToken
      AdminAPIMethods {..} = mkAdminAPI $ realm kc
  deleteClient resourceID

deleteClientByClientIDQuery :: KeycloakClient -> AuthToken -> ClientID -> SC.ClientM S.NoContent
deleteClientByClientIDQuery kc authToken clientID = do
  let APIMethods {..} = mkApiMethods
      AuthenticatedAPIMethods {..} = mkAuthenticatedAPI authToken
      AdminAPIMethods {..} = mkAdminAPI $ realm kc
  showClientByClientIDQuery kc authToken clientID >>= \case
    Nothing -> return S.NoContent
    Just clientInfo -> deleteClient $ cwiId clientInfo

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

newtype ResourceID = ResourceID {unResourceID :: Text}
  deriving (Generic)

instance Show ResourceID where
  show = T.unpack . unResourceID

instance FromJSON ResourceID where
  parseJSON =
    Aeson.withText "id" (pure . ResourceID)

instance S.FromHttpApiData ResourceID where
  -- The url piece is the complete URL, including the hostname. We
  -- assume the ResourceID is the last path of the URL.
  parseUrlPiece = fmap ResourceID . last' . T.splitOn "/"
    where
      last' [] = Left "could not parse resourceID"
      last' [x] = Right x
      last' (_ : xs) = last' xs

instance S.ToHttpApiData ResourceID where
  toUrlPiece = unResourceID

data ClientInfo = ClientInfo
  { ciClientId :: Text,
    ciRootUrl :: Maybe Text,
    ciProtocol :: Text,
    ciConsentRequired :: Bool,
    ciStandardFlowEnabled :: Bool,
    ciImplicitFlowEnabled :: Bool,
    ciDirectAccessGrantsEnabled :: Bool,
    ciServiceAccountsEnabled :: Bool,
    ciAuthorizationServicesEnabled :: Maybe Bool,
    ciPublicClient :: Bool,
    ciFrontchannelLogout :: Bool,
    ciClientAuthenticatorType :: Text
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

data WithResourceID a = WithResourceID
  { cwiId :: ResourceID,
    cwiInfo :: a
  }
  deriving (Generic)

instance (Show a) => Show (WithResourceID a) where
  show (WithResourceID id' info) = T.unpack (unResourceID id') <> ":\n" <> show info

instance (FromJSON a) => FromJSON (WithResourceID a) where
  parseJSON v =
    WithResourceID
      <$> Aeson.withObject "id" (.: "id") v
        <*> Aeson.parseJSON v

instance (ToJSON a) => ToJSON (WithResourceID a) where
  toJSON (WithResourceID id' info) = case toJSON info of
    Aeson.Object hashMap -> Aeson.Object (hashMap <> HashMap.singleton "id" (Aeson.String (unResourceID id')))
    other -> other

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

type AdminAPI =
  "admin"
    :> "realms"
    :> S.Capture "realm" Realm
    :> "clients"
    :> ( S.ReqBody '[S.JSON] ClientInfo
           :> S.Post '[S.OctetStream] (S.Headers '[S.Header "Location" ResourceID] S.NoContent)
           :<|> S.Capture "resourceId" ResourceID
             :> "protocol-mappers"
             :> "models"
             :> S.ReqBody '[S.JSON] Protocol
             :> S.Post '[S.JSON] S.NoContent
           :<|> S.QueryParam "clientId" ClientID :> S.Get '[S.JSON] [WithResourceID ClientInfo]
           :<|> S.Capture "resourceID" ResourceID
             :> S.Get '[S.JSON] (WithResourceID ClientInfo)
           :<|> S.Capture "resourceID" ResourceID
             :> S.Delete '[S.JSON] S.NoContent
       )

data APIMethods = APIMethods
  { requestAuthToken :: Realm -> ProtocolName -> TokenRequest -> SC.ClientM AuthToken,
    mkAuthenticatedAPI :: AuthToken -> AuthenticatedAPIMethods
  }

newtype AuthenticatedAPIMethods = AuthenticatedAPIMethods
  { mkAdminAPI :: Realm -> AdminAPIMethods
  }

data AdminAPIMethods = AdminAPIMethods
  { createClient :: ClientInfo -> SC.ClientM (S.Headers '[S.Header "Location" ResourceID] S.NoContent),
    addProtocolMapper :: ResourceID -> Protocol -> SC.ClientM S.NoContent,
    listClients :: Maybe ClientID -> SC.ClientM [WithResourceID ClientInfo],
    getClient :: ResourceID -> SC.ClientM (WithResourceID ClientInfo),
    deleteClient :: ResourceID -> SC.ClientM S.NoContent
  }

mkApiMethods :: APIMethods
mkApiMethods = APIMethods {..}
  where
    client = SC.client (Proxy :: Proxy API)

    requestAuthToken :<|> authenticatedAPI = client

    mkAuthenticatedAPI authToken = AuthenticatedAPIMethods {..}
      where
        adminAPI = authenticatedAPI (Just authToken)

        mkAdminAPI realm = AdminAPIMethods {..}
          where
            createClient :<|> addProtocolMapper :<|> listClients :<|> getClient :<|> deleteClient = adminAPI realm

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
