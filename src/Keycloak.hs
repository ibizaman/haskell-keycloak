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
    User (..),
    userQueries,
    RoleMapping (..),
    UserRoleMappingQueries (..),
    roleMappingQueries,
    Error (..),
    Status (..),
    KeycloakError (..),
    parseError,
  )
where

-- https://github.com/keycloak/keycloak-documentation/blob/master/server_admin/topics/admin-cli.adoc

import Control.Monad.Catch (MonadThrow (throwM))
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
      AuthenticatedAPIQueries {..} = mkAuthenticatedAPI authToken
      RealmAPIQueries {..} = mkRealmAPI $ realm kc
      ClientAPIQueries {..} = mkClientsAPI
  mkAdminAPI

secretQueries :: KeycloakClient -> AuthToken -> ClientAPIQueries
secretQueries kc authToken = do
  let APIQueries {..} = mkApiQueries
      AuthenticatedAPIQueries {..} = mkAuthenticatedAPI authToken
      RealmAPIQueries {..} = mkRealmAPI $ realm kc
  mkClientsAPI

protocolMapperQueries :: KeycloakClient -> AuthToken -> Rest.ResourceID -> Rest.APIQueries ProtocolName ProtocolMapper
protocolMapperQueries kc authToken clientId = do
  let APIQueries {..} = mkApiQueries
      AuthenticatedAPIQueries {..} = mkAuthenticatedAPI authToken
      RealmAPIQueries {..} = mkRealmAPI $ realm kc
      ClientAPIQueries {..} = mkClientsAPI
  mkProtocolMappersAPI clientId

userQueries :: KeycloakClient -> AuthToken -> Rest.APIQueries Text User
userQueries kc authToken = do
  let APIQueries {..} = mkApiQueries
      AuthenticatedAPIQueries {..} = mkAuthenticatedAPI authToken
      RealmAPIQueries {..} = mkRealmAPI $ realm kc
      UserAPIQueries {..} = mkUserAPI
  mkManageUserAPI

roleMappingQueries :: KeycloakClient -> AuthToken -> Rest.ResourceID -> Rest.ResourceID -> UserRoleMappingQueries
roleMappingQueries kc authToken userId clientId = do
  let APIQueries {..} = mkApiQueries
      AuthenticatedAPIQueries {..} = mkAuthenticatedAPI authToken
      RealmAPIQueries {..} = mkRealmAPI $ realm kc
      UserAPIQueries {..} = mkUserAPI
  mkRoleMappingAPI userId clientId

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

data User = User
  { uAccess :: Maybe (Map String Bool),
    uAttributes :: Maybe (Map String String),
    uClientRoles :: Maybe (Map String String),
    uCreatedTimestamps :: Maybe Int,
    uDisableCredentialTypes :: Maybe [Text],
    uEmail :: Maybe Text,
    uEmailVerified :: Maybe Bool,
    uEnabled :: Maybe Bool,
    uFederationLink :: Maybe Text,
    uFirstName :: Maybe Text,
    uGroups :: Maybe [Text],
    uLastName :: Maybe Text,
    uNotBefore :: Maybe Int,
    uOrigin :: Maybe Text,
    uRealmRoles :: Maybe [Text],
    uRequiredActions :: Maybe [Text],
    uSelf :: Maybe Text,
    uServiceAccountClientId :: Maybe Text,
    uUsername :: Text
  }
  deriving (Generic)

instance ToJSON User where
  toJSON =
    Aeson.genericToJSON
      ( Aeson.defaultOptions
          { Aeson.fieldLabelModifier = removePrefix "u",
            Aeson.omitNothingFields = True
          }
      )

instance FromJSON User where
  parseJSON =
    Aeson.genericParseJSON
      ( Aeson.defaultOptions
          { Aeson.fieldLabelModifier = removePrefix "u"
          }
      )

data RoleMapping = RoleMapping
  { rmAttributes :: Maybe (Map Text Text),
    rmClientRole :: Maybe Bool,
    rmComposite :: Maybe Bool,
    rmContainterID :: Maybe Text,
    rmDescription :: Maybe Text,
    rmName :: Text
  }
  deriving (Generic)

instance FromJSON RoleMapping where
  parseJSON =
    Aeson.genericParseJSON
      ( Aeson.defaultOptions
          { Aeson.fieldLabelModifier = removePrefix "rm"
          }
      )

instance ToJSON RoleMapping where
  toJSON =
    Aeson.genericToJSON
      ( Aeson.defaultOptions
          { Aeson.fieldLabelModifier = removePrefix "rm",
            Aeson.omitNothingFields = True
          }
      )

type API =
  AuthAPI
    :<|> S.Header "Authorization" AuthToken
    :> AuthenticatedAPI

data APIQueries = APIQueries
  { requestAuthToken :: Realm -> ProtocolType -> TokenRequest -> SC.ClientM AuthToken,
    mkAuthenticatedAPI :: AuthToken -> AuthenticatedAPIQueries
  }

type AuthAPI =
  "realms"
    :> S.Capture "realm" Realm
    :> "protocol"
    :> S.Capture "protocolType" ProtocolType
    :> "token"
    :> S.ReqBody '[S.FormUrlEncoded] TokenRequest
    :> S.Post '[S.JSON] AuthToken

type AuthenticatedAPI =
  "admin"
    :> "realms"
    :> S.Capture "realm" Realm
    :> RealmAPI

newtype AuthenticatedAPIQueries = AuthenticatedAPIQueries
  { mkRealmAPI :: Realm -> RealmAPIQueries
  }

type RealmAPI =
  ( "clients"
      :> ( ClientAPI
             :<|> SecretAPI
             :<|> ProtocolMapperAPI
         )
  )
    :<|> ( "users"
             :> ( UserAPI
                    :<|> RoleMappingAPI
                )
         )

data RealmAPIQueries = RealmAPIQueries
  { mkClientsAPI :: ClientAPIQueries,
    mkUserAPI :: UserAPIQueries
  }

type ClientAPI = Rest.API (S.QueryParam "clientId" Text) ClientInfo

type SecretAPI =
  S.Capture "resourceID" Rest.ResourceID
    :> "client-secret"
    :> S.Get '[S.JSON] ClientSecret

type ProtocolMapperAPI =
  S.Capture "resourceID" Rest.ResourceID
    :> "protocol-mappers"
    :> "models"
    :> Rest.API (S.QueryParam "name" ProtocolName) ProtocolMapper

type UserAPI = Rest.API (S.QueryParam "username" Text) User

type RoleMappingAPI =
  S.Capture "userID" Rest.ResourceID
    :> "role-mappings"
    :> "clients"
    :> S.Capture "clientID" Rest.ResourceID
    :> ( S.Get '[S.JSON] [Rest.WithResourceID RoleMapping]
           :<|> "available" :> S.Get '[S.JSON] [Rest.WithResourceID RoleMapping]
           :<|> S.ReqBody '[S.JSON] [Rest.WithResourceID RoleMapping] :> S.Post '[S.OctetStream] S.NoContent
           :<|> S.ReqBody '[S.JSON] [Rest.WithResourceID RoleMapping] :> S.Delete '[S.JSON] S.NoContent
       )

data ClientAPIQueries = ClientAPIQueries
  { mkAdminAPI :: Rest.APIQueries Text ClientInfo,
    getSecret :: Rest.ResourceID -> SC.ClientM Secret,
    mkProtocolMappersAPI :: Rest.ResourceID -> Rest.APIQueries ProtocolName ProtocolMapper
  }

data UserAPIQueries = UserAPIQueries
  { mkManageUserAPI :: Rest.APIQueries Text User,
    mkRoleMappingAPI :: Rest.ResourceID -> Rest.ResourceID -> UserRoleMappingQueries
  }

data UserRoleMappingQueries = UserRoleMappingQueries
  { list :: SC.ClientM [Rest.WithResourceID RoleMapping],
    listAvailable :: SC.ClientM [Rest.WithResourceID RoleMapping],
    get :: Rest.ResourceID -> SC.ClientM (Rest.WithResourceID RoleMapping),
    getByName :: Text -> SC.ClientM (Rest.WithResourceID RoleMapping),
    add :: Rest.ResourceID -> SC.ClientM S.NoContent,
    delete :: Rest.ResourceID -> SC.ClientM S.NoContent
  }

mkApiQueries :: APIQueries
mkApiQueries = APIQueries {..}
  where
    client = SC.client (Proxy :: Proxy API)

    requestAuthToken :<|> authenticatedAPI = client

    mkAuthenticatedAPI authToken = AuthenticatedAPIQueries {..}
      where
        realmAPI = authenticatedAPI (Just authToken)

        mkRealmAPI realm = RealmAPIQueries {..}
          where
            clientsAPI :<|> usersAPI = realmAPI realm

            mkClientsAPI = ClientAPIQueries {..}
              where
                adminAPI :<|> getSecret' :<|> protocolMappersAPI = clientsAPI

                mkAdminAPI = Rest.mkAPIQueries adminAPI ciClientId

                getSecret = fmap secretValue . getSecret'

                mkProtocolMappersAPI resourceID = Rest.mkAPIQueries (protocolMappersAPI resourceID) pName

            mkUserAPI = UserAPIQueries {..}
              where
                userAPI :<|> roleMappingAPI = usersAPI

                mkManageUserAPI = Rest.mkAPIQueries userAPI uUsername

                mkRoleMappingAPI userID clientID =
                  let list :<|> available :<|> add' :<|> delete' = roleMappingAPI userID clientID
                      both = list >>= \l -> available >>= \a -> return (l ++ a)
                      filter' = \rid ->
                        ( \case
                            [x] -> return x
                            [] -> throwM Rest.NoItemFound
                            _ -> throwM Rest.TooManyItemsFound
                        )
                          . filter (\v -> Rest.resourceID v == rid)
                      filterByName' = \name ->
                        ( \case
                            [x] -> return x
                            [] -> throwM Rest.NoItemFound
                            _ -> throwM Rest.TooManyItemsFound
                        )
                          . filter (\v -> rmName (Rest.resourceInfo v) == name)
                   in UserRoleMappingQueries
                        { list = list,
                          listAvailable = available,
                          get = \rid -> list >>= filter' rid,
                          getByName = \name -> both >>= filterByName' name,
                          add = \name -> available >>= filter' name >>= \x -> add' [x],
                          delete = \name -> list >>= filter' name >>= \x -> delete' [x]
                        }

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
