-- |
module Args
  ( Args (..),
    Command (..),
    Realm (..),
    Server (..),
    IP (..),
    ServerIP (..),
    Subdomain (..),
    getArgs,
  )
where

import Data.Bifunctor (Bifunctor (bimap))
import Data.Char (toLower)
import qualified Data.List as List
import Data.List.NonEmpty
  ( NonEmpty,
    some1,
  )
import Data.Text (Text)
import qualified Data.Text as T
import GHC.Generics (Generic)
import qualified Keycloak
import Options.Applicative
  ( Alternative ((<|>)),
    (<**>),
  )
import qualified Options.Applicative as Opts
import qualified Options.Applicative.Help.Pretty as P
import qualified Options.Generic as OptGen
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

data Command
  = Authenticate
  | CreateClient Keycloak.Realm Keycloak.ClientInfo
  | ListClients Keycloak.Realm
  | ShowClient Keycloak.Realm (NonEmpty Keycloak.ResourceID)
  | DeleteClient Keycloak.Realm (NonEmpty Keycloak.ResourceID)

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
              ( ShowClient <$> realmParser
                  <*> some1
                    ( Opts.argument
                        (Keycloak.ResourceID <$> Opts.str)
                        (Opts.metavar "CLIENTID")
                    )
              )
              (Opts.progDesc "Show a client")
          )
        <> Opts.command
          "delete"
          ( Opts.info
              ( DeleteClient <$> realmParser
                  <*> some1
                    ( Opts.argument
                        (Keycloak.ResourceID <$> Opts.str)
                        (Opts.metavar "CLIENTID")
                    )
              )
              (Opts.progDesc "Delete a client")
          )
    )

realmParser :: Opts.Parser Keycloak.Realm
realmParser =
  Opts.option
    (Keycloak.Realm <$> Opts.str)
    (Opts.long "realm" <> Opts.metavar "REALM")

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
