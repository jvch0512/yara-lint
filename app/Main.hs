module Main (main) where

import qualified Data.ByteString.Char8 as B
import Control.Exception (SomeException, try)
import Control.Monad (filterM, forM)
import Data.List (isSuffixOf, sort)
import System.Directory
import System.Environment (getArgs)
import System.Exit
import System.FilePath (makeRelative, takeFileName, (</>))
import System.IO

import Yara

usage :: IO ExitCode
usage = do
  hPutStrLn stderr "usage: yara-lint PATH [--tsv] [--fail-on medium|high|critical]\nExit: 0 ok, 1 findings at or above --fail-on, 2 bad input."
  return (ExitFailure 2)

data Opts = Opts {oPath :: Maybe FilePath, oTsv :: Bool, oFail :: Maybe String}

parseArgs :: [String] -> Maybe Opts
parseArgs = go (Opts Nothing False Nothing)
  where
    go o [] = Just o
    go o ("--tsv" : r) = go o {oTsv = True} r
    go o ("--fail-on" : v : r)
      | v `elem` ["medium", "high", "critical"] = go o {oFail = Just v} r
      | otherwise = Nothing
    go _ ["--fail-on"] = Nothing
    go o (a : r)
      | take 1 a == "-" && length a > 1 = Nothing
      | otherwise = case oPath o of
          Nothing -> go o {oPath = Just a} r
          Just _ -> Nothing

isYara :: FilePath -> Bool
isYara p = ".yar" `isSuffixOf` p || ".yara" `isSuffixOf` p

walk :: Int -> FilePath -> IO [FilePath]
walk depth dir
  | depth > 30 = return []
  | otherwise = do
      r <- try (listDirectory dir) :: IO (Either SomeException [FilePath])
      case r of
        Left _ -> return []
        Right names -> do
          let full = [dir </> n | n <- sort names, n /= ".git"]
          links <- filterM (\p -> either (const True) id <$> (try (pathIsSymbolicLink p) :: IO (Either SomeException Bool))) full
          let plain = filter (`notElem` links) full
          dirs <- filterM doesDirectoryExist plain
          files <- filterM doesFileExist plain
          sub <- forM dirs (walk (depth + 1))
          return (filter isYara files ++ concat sub)

readText :: FilePath -> IO String
readText p = do
  r <- try (do sz <- getFileSize p
               if sz > 50000000 then return B.empty else B.readFile p) :: IO (Either SomeException B.ByteString)
  return (either (const "") B.unpack r)

main :: IO ()
main = do
  hSetEncoding stdout utf8
  args <- getArgs
  case parseArgs args of
    Nothing -> usage >>= exitWith
    Just (Opts Nothing _ _) -> usage >>= exitWith
    Just (Opts (Just path0) tsv failOn) -> do
      isFile <- doesFileExist path0
      isDir <- doesDirectoryExist path0
      if not isFile && not isDir
        then hPutStrLn stderr ("error: no such file or directory: " ++ path0) >> exitWith (ExitFailure 2)
        else do
          let path = if length path0 > 1 then reverse (dropWhile (== '/') (reverse path0)) else path0
          paths <- if isDir then (\fs -> sort fs) <$> walk 0 path else return [path]
          let rel p = if isDir then makeRelative path p else takeFileName p
          texts <- forM paths $ \p -> do t <- readText p; return (rel p, t)
          let fs = lintFiles texts
              n = length paths
              hd = show n ++ " files, " ++ show (length fs) ++ " findings"
              whereOf f = if fLine f > 0 then fFile f ++ ":" ++ show (fLine f) else fFile f
              render f
                | tsv = [concatMap id [fSev f, "\t", fRule f, "\t", whereOf f, "\t", fMsg f]]
                | otherwise =
                    [ padRight 8 (map up (fSev f)) ++ " " ++ fRule f ++ " " ++ whereOf f
                    , "         " ++ fMsg f
                    ]
              padRight k s = s ++ replicate (k - length s) ' '
              up c = if c >= 'a' && c <= 'z' then toEnum (fromEnum c - 32) else c
          putStr (unlines ((if tsv then "# " ++ hd else hd) : concatMap render fs))
          hFlush stdout
          case failOn of
            Just lvl | any (\f -> rank (fSev f) <= rank lvl) fs -> exitWith (ExitFailure 1)
            _ -> exitSuccess
