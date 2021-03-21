{-# LANGUAGE FlexibleInstances #-}

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
  = ClientID Keycloak.ClientID
  | ResourceID Rest.ResourceID

data Command
  = Authenticate
  | CreateClient Keycloak.Realm Keycloak.ClientInfo
  | ListClients Keycloak.Realm
  | ShowClient Keycloak.Realm (NonEmpty ClientIdentifier)
  | DeleteClient Keycloak.Realm (NonEmpty ClientIdentifier)
  | ShowSecret Keycloak.Realm ClientIdentifier

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
            (Opts.info clientParser (Opts.progDesc "Manage clients"))
      )

clientParser :: Opts.Parser Command
clientParser =
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

clientIdentifierParser :: Opts.Parser ClientIdentifier
clientIdentifierParser =
  Opts.option
    (ResourceID . Rest.ResourceID <$> Opts.str)
    (Opts.long "id" <> Opts.metavar "RESOURCEID")
    <|> Opts.option
      (ClientID . Keycloak.ClientID <$> Opts.str)
      (Opts.long "clientid" <> Opts.metavar "CLIENTID")

realmParser :: Opts.Parser Keycloak.Realm
realmParser =
  Opts.option
    (Keycloak.Realm <$> Opts.str)
    (Opts.long "realm" <> Opts.metavar "REALM")

instance OptGen.ParseRecord Keycloak.ClientInfo

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
