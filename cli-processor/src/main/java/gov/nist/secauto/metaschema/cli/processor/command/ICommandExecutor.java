/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.cli.processor.command;

import gov.nist.secauto.metaschema.cli.processor.CLIProcessor.CallingContext;

import org.apache.commons.cli.CommandLine;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * An abstract base class that implements the {@link ICommandExecutor}
 * interface, providing common functionality for command execution
 * implementations. Concrete subclasses must implement the {@link #execute()}
 * method to define specific command behavior.
 */
@FunctionalInterface
public interface ICommandExecutor {
  /**
   * Execute the command operation.
   *
   * @throws CommandExecutionException
   *           if an error occurred while executing the command operation
   */
  void execute() throws CommandExecutionException;

  /**
   * Create a new command executor.
   *
   * @param callingContext
   *          the context of the command execution
   * @param commandLine
   *          the parsed command line details
   * @param function
   *          a function that accepts a calling context and command line
   *          information
   * @return the executor instance
   */
  @NonNull
  static ICommandExecutor using(
      @NonNull CallingContext callingContext,
      @NonNull CommandLine commandLine,
      @NonNull ExecutionFunction function) {
    return () -> function.execute(callingContext, commandLine);
  }

  /**
   * This functional interface represents a method that is used to execute a
   * command operation.
   */
  @FunctionalInterface
  interface ExecutionFunction {
    /**
     * Execute a command operation.
     *
     * @param callingContext
     *          the context of the command execution
     * @param commandLine
     *          the parsed command line details
     * @throws CommandExecutionException
     *           if an error occurred while executing the command operation
     */
    void execute(
        @NonNull CallingContext callingContext,
        @NonNull CommandLine commandLine) throws CommandExecutionException;
  }
}
