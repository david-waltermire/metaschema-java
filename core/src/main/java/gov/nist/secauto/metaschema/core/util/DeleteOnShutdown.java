/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.util;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Used to perform cleanup on shutdown.
 */
@SuppressWarnings("PMD.DoNotUseThreads")
public final class DeleteOnShutdown {
  private static Set<Path> paths = new LinkedHashSet<>();
  private static final Lock LOCK = new ReentrantLock();

  static {
    Runtime.getRuntime().addShutdownHook(
        new Thread(DeleteOnShutdown::shutdownHook));
  }

  @SuppressWarnings("PMD.NullAssignment")
  private static void shutdownHook() {
    LOCK.lock();
    try {
      Set<Path> localSet = new LinkedHashSet<>(paths);
      paths = null;
      localSet.forEach(path -> {
        try {
          Files.walkFileTree(path,
              new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult postVisitDirectory(
                    Path dir, IOException exc) throws IOException {
                  Files.delete(dir);
                  return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(
                    Path file, BasicFileAttributes attrs)
                    throws IOException {
                  Files.delete(file);
                  return FileVisitResult.CONTINUE;
                }
              });
        } catch (IOException ex) {
          // this is a best effort, ignore the error
        }
      });
    } finally {
      LOCK.unlock();
    }
  }

  /**
   * Register a new path to be deleted on JVM termination.
   * <p>
   * If the path is a directory, then its contents will also be deleted.
   *
   * @param path
   *          the path to delete
   */
  public static void register(Path path) {
    LOCK.lock();
    try {
      if (paths == null) {
        throw new IllegalStateException("ShutdownHook already in progress.");
      }
      paths.add(path);
    } finally {
      LOCK.unlock();
    }
  }

  private DeleteOnShutdown() {
    // disable construction
  }

}
