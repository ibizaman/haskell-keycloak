{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}

module Main
  ( main,
  )
where

import qualified Args
-- import qualified ConfigFile
import Control.Applicative (Alternative ((<|>)))
import Control.Monad
  ( forM_,
    when,
  )
import qualified Data.Aeson.Encode.Pretty as AesonP
import qualified Data.ByteString.Lazy.Char8 as BS
import qualified Data.List as List
import Data.List.NonEmpty (NonEmpty ((:|)))
import Data.Maybe (fromMaybe)
import Data.Text
  ( Text,
    isPrefixOf,
  )
import qualified Data.Text as T
import qualified Env
-- import HumanReadable
--   ( HumanReadable,
--     printForHumans,
--   )
-- import qualified IP
import qualified Keycloak
import Network.HTTP.Client.TLS (newTlsManager)
import qualified Options.Applicative.Help as Help
import qualified Rest
import qualified Servant as S
import qualified Servant.Client as SC
import System.Environment (getProgName)

main :: IO ()
main =
  Args.getArgs >>= \args -> do
    env <- Env.getEnv
    -- configFile <-
    --   eitherToMaybe
    --     <$> ConfigFile.parse
    --       (maybe ConfigFile.defaultConfigFiles (:| []) $ Args.configFile args)
    let auth = Env.auth env
    -- let auth =
    --       Args.credentials args
    --         <|> Env.auth env
    --         <|> (ConfigFile.apiKey <$> configFile)
    -- let endpoint = Env.endpoint env
    let endpoint = SC.BaseUrl SC.Http "arsenic" 8081 "auth"
    case auth of
      Nothing -> do
        progName <- getProgName
        Help.putDoc $
          "Please set the credentials. Run "
            <> Help.underline (Help.text progName <> " credentials")
            <> " for more info."
            <> Help.hardline
      Just auth' -> command endpoint auth' (Args.command args)
  where
    command endpoint auth Args.Authenticate = do
      let kc = Keycloak.mkClient auth (Keycloak.Realm "master")
      run' endpoint (Keycloak.authenticateQuery kc Keycloak.OpenidConnect)
        >>= display
    command endpoint auth (Args.CreateClient realm clientInfo) = do
      let kc = Keycloak.mkClient auth (Keycloak.Realm "master")
      run' endpoint (Keycloak.authenticateQuery kc Keycloak.OpenidConnect)
        >>= \case
          Left err -> displayErr $ Keycloak.parseError err
          Right token -> do
            let kc' = Keycloak.mkClient auth realm
            run'
              endpoint
              (Rest.create (Keycloak.clientQueries kc' token) clientInfo)
              >>= \case
                Left err' -> displayErr $ Keycloak.parseError err'
                Right clientID -> print clientID
    command endpoint auth (Args.ListClients realm) = do
      let kc = Keycloak.mkClient auth (Keycloak.Realm "master")
      run' endpoint (Keycloak.authenticateQuery kc Keycloak.OpenidConnect)
        >>= \case
          Left err -> displayErr $ Keycloak.parseError err
          Right token -> do
            let kc' = Keycloak.mkClient auth realm
            run' endpoint (Rest.list (Keycloak.clientQueries kc' token))
              >>= \case
                Left err' -> displayErr $ Keycloak.parseError err'
                Right cis ->
                  forM_ cis $
                    putStrLn . \ciwr ->
                      T.unpack (Rest.unResourceID (Rest.resourceID ciwr))
                        <> " "
                        <> T.unpack
                          (Keycloak.ciClientId (Rest.resourceInfo ciwr))
    command endpoint auth (Args.ShowClient realm clientIDs) = do
      let kc = Keycloak.mkClient auth (Keycloak.Realm "master")
      run' endpoint (Keycloak.authenticateQuery kc Keycloak.OpenidConnect)
        >>= \case
          Left err -> displayErr $ Keycloak.parseError err
          Right token -> do
            let kc' = Keycloak.mkClient auth realm
            forM_ clientIDs $ \c ->
              ( case c of
                  Args.ClientID clientID ->
                    run'
                      endpoint
                      ( Rest.getByName
                          (Keycloak.clientQueries kc' token)
                          clientID
                      )
                      >>= either
                        (displayErr . Keycloak.parseError)
                        (BS.putStrLn . AesonP.encodePretty)
                  Args.ResourceID resourceID ->
                    run'
                      endpoint
                      (Rest.get (Keycloak.clientQueries kc' token) resourceID)
                      >>= either
                        (displayErr . Keycloak.parseError)
                        (BS.putStrLn . AesonP.encodePretty)
              )
    command endpoint auth (Args.DeleteClient realm clientIDs) = do
      let kc = Keycloak.mkClient auth (Keycloak.Realm "master")
      run' endpoint (Keycloak.authenticateQuery kc Keycloak.OpenidConnect)
        >>= \case
          Left err -> displayErr $ Keycloak.parseError err
          Right token -> do
            let kc' = Keycloak.mkClient auth realm
            forM_ clientIDs $ \c ->
              ( case c of
                  Args.ClientID clientID ->
                    run'
                      endpoint
                      ( Rest.deleteByName
                          (Keycloak.clientQueries kc' token)
                          clientID
                      )
                  Args.ResourceID resourceID ->
                    run'
                      endpoint
                      (Rest.delete (Keycloak.clientQueries kc' token) resourceID)
              )
                >>= \case
                  Left err' -> displayErr $ Keycloak.parseError err'
                  Right _ -> return ()
    command endpoint auth (Args.ShowSecret realm clientIdentifier) = do
      let kc = Keycloak.mkClient auth (Keycloak.Realm "master")
      run' endpoint (Keycloak.authenticateQuery kc Keycloak.OpenidConnect)
        >>= \case
          Left err -> displayErr $ Keycloak.parseError err
          Right token -> do
            let kc' = Keycloak.mkClient auth realm
            ( case clientIdentifier of
                Args.ClientID clientID ->
                  run'
                    endpoint
                    ( Rest.getByName (Keycloak.clientQueries kc' token) clientID
                        >>= ( \Rest.WithResourceID {resourceID} ->
                                Keycloak.getSecret
                                  (Keycloak.secretQueries kc' token)
                                  resourceID
                            )
                    )
                    >>= either
                      (displayErr . Keycloak.parseError)
                      (BS.putStrLn . AesonP.encodePretty)
                Args.ResourceID resourceID ->
                  run'
                    endpoint
                    ( Keycloak.getSecret
                        (Keycloak.secretQueries kc' token)
                        resourceID
                    )
                    >>= either
                      (displayErr . Keycloak.parseError)
                      (BS.putStrLn . AesonP.encodePretty)
              )

display :: Show a => Either SC.ClientError a -> IO ()
display (Left err) = displayErr $ Keycloak.parseError err
display (Right x) = print x

run' :: SC.BaseUrl -> SC.ClientM a -> IO (Either SC.ClientError a)
run' endpoint query = do
  manager' <- newTlsManager
  SC.runClientM query (SC.mkClientEnv manager' endpoint)

displayErr :: Keycloak.Error -> IO ()
displayErr = displayErr' Nothing

displayErr' :: Maybe Text -> Keycloak.Error -> IO ()
displayErr' prefix err =
  let prefix' = T.unpack $ fromMaybe "" prefix
   in case err of
        Keycloak.Error Keycloak.Status {statusCode, statusMessage} e ->
          putStrLn $
            prefix'
              <> "got an error from Keycloak: ["
              <> show statusCode
              <> "] "
              <> statusMessage
              <> ":\n"
              <> printError e
          where
            printError :: Keycloak.KeycloakError -> String
            printError Keycloak.KeycloakError {..} =
              maybe "" (\e' -> "[" <> e' <> "] ") keycloakError
                <> fromMaybe "" keycloakErrorDescription
                <> fromMaybe "" keycloakErrorMessage
        Keycloak.DecodeError Keycloak.Status {statusCode, statusMessage} e decodeError ->
          putStrLn $
            prefix'
              <> "got an error \""
              <> decodeError
              <> "\" while decoding a response from Keycloak ["
              <> show statusCode
              <> "] "
              <> statusMessage
              <> ": "
              <> e
        Keycloak.ConnectionError e ->
          putStrLn $
            prefix'
              <> "got a connection error while talking with Keycloak: "
              <> e
        Keycloak.OtherError Keycloak.Status {statusCode, statusMessage} e ->
          putStrLn $
            prefix'
              <> "got an error status code from Keycloak ["
              <> show statusCode
              <> "] "
              <> statusMessage
              <> ": "
              <> e

mapLeft :: (a -> b) -> Either a c -> Either b c
mapLeft f (Left a) = Left $ f a
mapLeft _ (Right b) = Right b

mapRight :: (c -> d) -> Either a c -> Either a d
mapRight _ (Left a) = Left a
mapRight f (Right b) = Right $ f b

-- eitherToMaybe :: Either a b -> Maybe b
-- eitherToMaybe (Left _) = Nothing
-- eitherToMaybe (Right b) = Just b
