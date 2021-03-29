{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE LambdaCase #-}

-- |
module Args
  ( Args (..),
    Command (..),
    Realm (..),
    Server (..),
    IP (..),
    ServerIP (..),
    Subdomain (..),
    ClientIdentifier (..),
    ProtocolMapperIdentifier (..),
    getArgs,
  )
where

import Control.Monad (join)
import Data.Bifunctor (Bifunctor (bimap, second))
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
import Data.Typeable (Typeable)
import GHC.Generics (Generic)
import Generic.Data (Generically)
import qualified Keycloak
import Options.Applicative
  ( Alternative ((<|>)),
    (<**>),
  )
import qualified Options.Applicative as Opts
import qualified Options.Applicative.Help.Pretty as P
import qualified Options.Generic as OptGen
import qualified Rest
import Text.Read (readEither)
import Utils (splitOn)
import qualified Utils

data Args = Args
  { -- configFile  :: Maybe Text
    -- , credentials :: Maybe Godaddy.APIKey
    command :: Command
  }

newtype Realm = Realm {unRealm :: Text}

newtype Server = Server {unServer :: Text}

newtype IP = IP {unIP :: Text}

data ServerIP = ServerIP Server IP

newtype Subdomain = Subdomain {unSubdomain :: Text}

data ClientIdentifier
  = ClientID Text
  | ResourceID Rest.ResourceID

data ProtocolMapperIdentifier
  = ProtocolName Keycloak.ProtocolName
  | ProtocolResourceID Rest.ResourceID

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

argsParser :: Opts.Parser Args
argsParser =
  Args
    <$> Opts.hsubparser
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

clientIdentifierParser :: Opts.Parser ClientIdentifier
clientIdentifierParser =
  Opts.option
    (ResourceID . Rest.ResourceID <$> Opts.str)
    (Opts.long "id" <> Opts.metavar "RESOURCEID")
    <|> Opts.option
      (ClientID <$> Opts.str)
      (Opts.long "clientid" <> Opts.metavar "CLIENTID")

realmParser :: Opts.Parser Keycloak.Realm
realmParser =
  Opts.option
    (Keycloak.Realm <$> Opts.str)
    (Opts.long "realm" <> Opts.metavar "REALM")

protocolMapperIdentifierParser :: Opts.Parser ProtocolMapperIdentifier
protocolMapperIdentifierParser =
  Opts.option
    (ProtocolResourceID . Rest.ResourceID <$> Opts.str)
    (Opts.long "id" <> Opts.metavar "RESOURCEID")
    <|> Opts.option
      (ProtocolName . Keycloak.ProtocolName <$> Opts.str)
      (Opts.long "name" <> Opts.metavar "PROTOCOLNAME")

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
