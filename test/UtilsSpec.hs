module UtilsSpec
  ( spec,
  )
where

import qualified Test.Hspec as T
import qualified Utils as U

spec :: T.Spec
spec = do
  T.describe "splitOn" $ do
    T.it "returns nothing on empty list" $ U.joinAfter 2 [] `T.shouldBe` Nothing
