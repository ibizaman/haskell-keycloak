{-# LANGUAGE LambdaCase #-}

-- |
module ConfigFile
  ( ConfigFile (..),
    defaultConfigFiles,
    parse,
  )
where

import Control.Exception (tryJust)
import Data.Foldable (asum)
import qualified Data.Ini.Config as Config
import Data.List.NonEmpty (NonEmpty ((:|)))
import Data.Text (Text)
import qualified Data.Text as T
import qualified Env
import qualified Keycloak
import qualified System.Envy as Envy
import qualified System.IO.Error as Error

data ConfigFile = ConfigFile
  { endpoint :: Maybe Env.Endpoint,
    apiKey :: Maybe Keycloak.AuthCredentials
  }
  deriving (Show)

apikeyConfig :: Config.IniParser ConfigFile
apikeyConfig =
  ConfigFile
    <$> Config.sectionMb
      "HOST"
      ( Config.fieldOf "endpoint" $ \t -> case Config.string t of
          Left e -> Left e
          Right str -> case Envy.fromVar str of
            Nothing -> Left "could not parse endpoint"
            Just url -> Right url
      )
    <*> Config.sectionMb
      "AUTH"
      ( Keycloak.PasswordAuth
          <$> Config.fieldOf "username" Config.string
          <*> Config.fieldOf "password" Config.string
          <*> Config.fieldOf
            "clientid"
            (fmap Keycloak.ClientID . Config.string)
      )

parse :: NonEmpty Text -> IO (Either String ConfigFile)
parse = fmap asum . traverse parseFile
  where
    parseFile :: Text -> IO (Either String ConfigFile)
    parseFile file = do
      r <-
        \case
          Error e -> do
            Left $ "error in file " <> T.unpack file <> ": " <> e
          FileContent f -> case Config.parseIniFile f apikeyConfig of
            Left failure -> do
              Left $ "error in file " <> T.unpack file <> ": " <> failure
            Right v -> do
              Right v
          <$> readFileSafe file
      putStrLn $ show r

      return r

defaultConfigFiles :: NonEmpty Text
defaultConfigFiles = "keycloak.conf" :| ["/etc/hskeycloak/keycloak.conf"]

data File = Error String | FileContent Text

readFileSafe :: Text -> IO File
readFileSafe file =
  either Error (FileContent . T.pack)
    <$> tryJust handleException (readFile $ T.unpack file)
  where
    handleException :: IOError -> Maybe String
    handleException er
      | Error.isDoesNotExistError er = Just "does not exist"
      | Error.isPermissionError er = Just "permission error"
      | otherwise = Nothing
