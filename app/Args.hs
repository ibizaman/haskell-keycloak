{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE LambdaCase #-}

-- |
module Args
  ( Args (..),
    Command (..),
    ClientIdentifier (..),
    ProtocolMapperIdentifier (..),
    UserIdentifier (..),
    RoleMappingIdentifier (..),
    getArgs,
  )
where

import Data.Bifunctor (Bifunctor (second))
import Data.Char (toLower)
import qualified Data.List as List
import Data.List.NonEmpty
  ( NonEmpty,
    some1,
  )
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import qualified Data.Text as T
import qualified Env
import qualified Keycloak
import Options.Applicative
  ( Alternative ((<|>)),
    (<**>),
  )
import qualified Options.Applicative as Opts
import qualified Options.Applicative.Help.Pretty as P
import qualified Options.Generic as OptGen
import qualified Rest
import qualified System.Envy as Envy
import Text.Read (readEither)
import Utils (splitOn)
import qualified Utils

data Args = Args
  { configFile :: Maybe Text,
    credentials :: Maybe Keycloak.AuthCredentials,
    endpoint :: Maybe Env.Endpoint,
    command :: Command
  }

data ClientIdentifier
  = ClientID Text
  | ResourceID Rest.ResourceID

data ProtocolMapperIdentifier
  = ProtocolName Keycloak.ProtocolName
  | ProtocolResourceID Rest.ResourceID

data UserIdentifier
  = UserID Text
  | UserResourceID Rest.ResourceID

data RoleMappingIdentifier
  = RoleMappingID Text
  | RoleMappingResourceID Rest.ResourceID

data Command
  = Authenticate
  | CreateClient Keycloak.Realm Keycloak.ClientInfo
  | ListClients Keycloak.Realm
  | ShowClient Keycloak.Realm (NonEmpty ClientIdentifier)
  | DeleteClient Keycloak.Realm (NonEmpty ClientIdentifier)
  | ShowSecret Keycloak.Realm ClientIdentifier
  | CreateProtocol Keycloak.Realm ClientIdentifier Keycloak.ProtocolMapper
  | ListProtocols Keycloak.Realm ClientIdentifier
  | ShowProtocol Keycloak.Realm ClientIdentifier (NonEmpty ProtocolMapperIdentifier)
  | DeleteProtocol Keycloak.Realm ClientIdentifier (NonEmpty ProtocolMapperIdentifier)
  | ListUsers Keycloak.Realm
  | ShowUser Keycloak.Realm (NonEmpty UserIdentifier)
  | ListRoleMappings Keycloak.Realm UserIdentifier ClientIdentifier
  | ShowRoleMappings Keycloak.Realm UserIdentifier ClientIdentifier (NonEmpty RoleMappingIdentifier)
  | AddRoleMapping Keycloak.Realm UserIdentifier ClientIdentifier (NonEmpty RoleMappingIdentifier)
  | DeleteRoleMapping Keycloak.Realm UserIdentifier ClientIdentifier (NonEmpty RoleMappingIdentifier)

argsParser :: Opts.Parser Args
argsParser =
  Args
    <$> configFileParser
    <*> credentialsParser
    <*> baseUrlParser
    <*> commandParser

configFileParser :: Opts.Parser (Maybe Text)
configFileParser =
  Opts.optional $
    Opts.option
      Opts.str
      (Opts.long "config" <> Opts.metavar "CONFIGFILE" <> Opts.showDefault)

credentialsParser :: Opts.Parser (Maybe Keycloak.AuthCredentials)
credentialsParser =
  Opts.optional $
    Opts.option
      (Opts.maybeReader Keycloak.parseAuthCredentials)
      (Opts.long "credentials" <> Opts.metavar "CLIENTID:USERNAME:SECRET")

baseUrlParser :: Opts.Parser (Maybe Env.Endpoint)
baseUrlParser =
  Opts.optional $
    Opts.option
      (Opts.maybeReader Envy.fromVar)
      (Opts.long "endpoint" <> Opts.metavar "scheme://host:port/path")

commandParser :: Opts.Parser Command
commandParser =
  Opts.hsubparser
    ( Opts.command
        "authenticate"
        ( Opts.info
            (pure Authenticate)
            (Opts.progDesc "Authenticate to the Keycloak server")
        )
        <> Opts.command
          "client"
          (Opts.info clientsParser (Opts.progDesc "Manage clients"))
        <> Opts.command
          "protocolmapper"
          ( Opts.info
              protocolMappersParser
              (Opts.progDesc "Manage protocol mappers for clients")
          )
        <> Opts.command
          "user"
          (Opts.info usersParser (Opts.progDesc "Manage users"))
        <> Opts.command
          "rolemapping"
          ( Opts.info
              roleMappingParser
              (Opts.progDesc "Manage role mappings for users")
          )
    )

clientsParser :: Opts.Parser Command
clientsParser =
  Opts.hsubparser
    ( Opts.command
        "create"
        ( Opts.info
            (CreateClient <$> realmParser <*> clientInfoParser)
            (Opts.progDesc "Create a client")
        )
        <> Opts.command
          "list"
          ( Opts.info (ListClients <$> realmParser) (Opts.progDesc "List clients")
          )
        <> Opts.command
          "show"
          ( Opts.info
              (ShowClient <$> realmParser <*> some1 clientIdentifierParser)
              (Opts.progDesc "Show a client")
          )
        <> Opts.command
          "delete"
          ( Opts.info
              (DeleteClient <$> realmParser <*> some1 clientIdentifierParser)
              (Opts.progDesc "Delete a client")
          )
        <> Opts.command
          "secret"
          ( Opts.info
              (ShowSecret <$> realmParser <*> clientIdentifierParser)
              (Opts.progDesc "Show a client's secret")
          )
    )

protocolMappersParser :: Opts.Parser Command
protocolMappersParser =
  Opts.hsubparser
    ( Opts.command
        "create"
        ( Opts.info
            ( CreateProtocol
                <$> realmParser
                <*> clientIdentifierParser
                <*> protocolMapperParser
            )
            (Opts.progDesc "Create a protocol mapper")
        )
        <> Opts.command
          "list"
          ( Opts.info
              (ListProtocols <$> realmParser <*> clientIdentifierParser)
              (Opts.progDesc "List protocol mappers")
          )
        <> Opts.command
          "show"
          ( Opts.info
              ( ShowProtocol
                  <$> realmParser
                  <*> clientIdentifierParser
                  <*> some1 protocolMapperIdentifierParser
              )
              (Opts.progDesc "Show a protocol mapper")
          )
        <> Opts.command
          "delete"
          ( Opts.info
              ( DeleteProtocol
                  <$> realmParser
                  <*> clientIdentifierParser
                  <*> some1 protocolMapperIdentifierParser
              )
              (Opts.progDesc "Delete a protocol mapper")
          )
    )

usersParser :: Opts.Parser Command
usersParser =
  Opts.hsubparser
    ( Opts.command
        "list"
        (Opts.info (ListUsers <$> realmParser) (Opts.progDesc "List users"))
        <> Opts.command
          "show"
          ( Opts.info
              (ShowUser <$> realmParser <*> some1 userIdentifierParser)
              (Opts.progDesc "Show a user")
          )
    )

roleMappingParser :: Opts.Parser Command
roleMappingParser =
  Opts.hsubparser
    ( Opts.command
        "list"
        ( Opts.info
            ( ListRoleMappings
                <$> realmParser
                <*> userIdentifierParser
                <*> clientIdentifierParser
            )
            (Opts.progDesc "List used and available role mappings for user")
        )
        <> Opts.command
          "show"
          ( Opts.info
              ( ShowRoleMappings
                  <$> realmParser
                  <*> userIdentifierParser
                  <*> clientIdentifierParser
                  <*> some1 roleMappingIdentifierParser
              )
              (Opts.progDesc "Show role mapping")
          )
        <> Opts.command
          "add"
          ( Opts.info
              ( AddRoleMapping
                  <$> realmParser
                  <*> userIdentifierParser
                  <*> clientIdentifierParser
                  <*> some1 roleMappingIdentifierParser
              )
              (Opts.progDesc "Add role mapping to user")
          )
        <> Opts.command
          "delete"
          ( Opts.info
              ( DeleteRoleMapping
                  <$> realmParser
                  <*> userIdentifierParser
                  <*> clientIdentifierParser
                  <*> some1 roleMappingIdentifierParser
              )
              (Opts.progDesc "Remote role mapping from user")
          )
    )

clientIdentifierParser :: Opts.Parser ClientIdentifier
clientIdentifierParser =
  Opts.option
    (ResourceID . Rest.ResourceID <$> Opts.str)
    (Opts.long "clientid" <> Opts.metavar "RESOURCEID")
    <|> Opts.option
      (ClientID <$> Opts.str)
      (Opts.long "clientname" <> Opts.metavar "CLIENTID")

realmParser :: Opts.Parser Keycloak.Realm
realmParser =
  Opts.option
    (Keycloak.Realm <$> Opts.str)
    (Opts.long "realm" <> Opts.metavar "REALM")

protocolMapperIdentifierParser :: Opts.Parser ProtocolMapperIdentifier
protocolMapperIdentifierParser =
  Opts.option
    (ProtocolResourceID . Rest.ResourceID <$> Opts.str)
    (Opts.long "pid" <> Opts.metavar "RESOURCEID")
    <|> Opts.option
      (ProtocolName . Keycloak.ProtocolName <$> Opts.str)
      (Opts.long "pname" <> Opts.metavar "PROTOCOLNAME")

userIdentifierParser :: Opts.Parser UserIdentifier
userIdentifierParser =
  Opts.option
    (UserResourceID . Rest.ResourceID <$> Opts.str)
    (Opts.long "userid" <> Opts.metavar "RESOURCEID")
    <|> Opts.option
      (UserID <$> Opts.str)
      (Opts.long "username" <> Opts.metavar "USERNAME")

roleMappingIdentifierParser :: Opts.Parser RoleMappingIdentifier
roleMappingIdentifierParser =
  Opts.option
    (RoleMappingResourceID . Rest.ResourceID <$> Opts.str)
    (Opts.long "rmid" <> Opts.metavar "RESOURCEID")
    <|> Opts.option
      (RoleMappingID <$> Opts.str)
      (Opts.long "rmname" <> Opts.metavar "NAME")

instance OptGen.ParseRecord Keycloak.ClientInfo

instance OptGen.ParseRecord Keycloak.ProtocolName

instance OptGen.ParseFields Keycloak.ProtocolName

instance OptGen.ParseField Keycloak.ProtocolName where
  readField = Opts.maybeReader (Just . Keycloak.ProtocolName . T.pack)

instance OptGen.ParseRecord Keycloak.ProtocolType

instance OptGen.ParseFields Keycloak.ProtocolType

instance OptGen.ParseField Keycloak.ProtocolType where
  readField =
    Opts.eitherReader
      ( \case
          "openid-connect" -> Right Keycloak.OpenidConnect
          t -> Left $ "Unkown protocol " <> t
      )

instance OptGen.ParseField (Map String String) where
  readField =
    Opts.eitherReader
      ( fmap Map.fromList
          . mapM
            ( \x ->
                maybeToEither ("Cannot parse " <> x <> "as 'KEY=VALUE'") $
                  Utils.splitStringOnLastChar '=' x
            )
          . splitOn (== ',')
      )

  metavar _ = "[KEY=VALUE[,KEY=VALUE]]"

instance OptGen.ParseField (Map String Bool) where
  readField =
    Opts.eitherReader
      ( fmap Map.fromList
          . f
          . mapM
            ( \x' ->
                maybeToEither ("Cannot parse " <> x' <> "as 'KEY=BOOL'") $
                  Utils.splitStringOnLastChar '=' x'
            )
          . splitOn (== ',')
      )
    where
      f :: Either String [(String, String)] -> Either String [(String, Bool)]
      f = (y =<<)

      y :: [(String, String)] -> Either String [(String, Bool)]
      y = mapM (x . w)

      w :: (String, String) -> (String, Either String Bool)
      w = second readEither

      x :: (String, Either String Bool) -> Either String (String, Bool)
      x = sequence

  metavar _ = "[KEY=BOOL[,KEY=BOOL]]"

instance OptGen.ParseField [Text] where
  readField = Opts.eitherReader (Right . fmap T.pack . splitOn (== ','))

clientInfoParser :: Opts.Parser Keycloak.ClientInfo
clientInfoParser =
  OptGen.parseRecordWithModifiers
    ( OptGen.defaultModifiers
        { OptGen.fieldNameModifier = fmap toLower . drop (length ("ci" :: String))
        }
    )

protocolMapperParser :: Opts.Parser Keycloak.ProtocolMapper
protocolMapperParser =
  Keycloak.ProtocolMapper
    <$> Opts.option
      (Keycloak.ProtocolName <$> Opts.str)
      (Opts.long "name" <> Opts.metavar "STRING")
    <*> pure Keycloak.OpenidConnect
    <*> Opts.option
      Opts.str
      (Opts.long "protocolmapper" <> Opts.metavar "STRING")
    <*> Opts.switch (Opts.long "consentrequired")
    <*> OptGen.parseRecordWithModifiers
      ( OptGen.defaultModifiers
          { OptGen.fieldNameModifier =
              fmap toLower
                . drop (length ("p" :: String))
          }
      )

getArgs :: IO Args
getArgs = Opts.customExecParser p opts
  where
    p = Opts.prefs Opts.showHelpOnEmpty
    opts =
      Opts.info
        (argsParser <**> Opts.helper)
        ( Opts.header "Keycloak cli"
            <> Opts.progDescDoc
              ( Just $
                  mintercalate
                    (P.hardline <> P.hardline)
                    ["This program allows you to manage a Keycloak server."]
              )
        )

mintercalate :: P.Doc -> [P.Doc] -> P.Doc
mintercalate separator = mconcat . List.intersperse separator

showAlwaysHelp :: a -> Opts.Parser a
showAlwaysHelp p =
  p <$ Opts.argument (Opts.eitherReader Left) (Opts.metavar "")

maybeToEither :: a -> Maybe b -> Either a b
maybeToEither _ (Just b) = Right b
maybeToEither a Nothing = Left a
