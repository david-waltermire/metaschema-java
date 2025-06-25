/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.cli.commands;

import gov.nist.secauto.metaschema.cli.processor.CLIProcessor.CallingContext;
import gov.nist.secauto.metaschema.cli.processor.ExitCode;
import gov.nist.secauto.metaschema.cli.processor.command.AbstractCommandExecutor;
import gov.nist.secauto.metaschema.cli.processor.command.AbstractTerminalCommand;
import gov.nist.secauto.metaschema.cli.processor.command.CommandExecutionException;
import gov.nist.secauto.metaschema.cli.processor.command.ExtraArgument;
import gov.nist.secauto.metaschema.core.model.MetaschemaException;
import gov.nist.secauto.metaschema.core.util.AutoCloser;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.databind.IBindingContext;
import gov.nist.secauto.metaschema.databind.io.Format;
import gov.nist.secauto.metaschema.databind.io.IBoundLoader;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Collection;
import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Used by implementing classes to provide a content conversion command.
 */
public abstract class AbstractConvertSubcommand
    extends AbstractTerminalCommand {
  private static final Logger LOGGER = LogManager.getLogger(AbstractConvertSubcommand.class);

  @NonNull
  private static final String COMMAND = "convert";
  @NonNull
  private static final List<ExtraArgument> EXTRA_ARGUMENTS = ObjectUtils.notNull(List.of(
      ExtraArgument.newInstance("source-file-or-URL", true),
      ExtraArgument.newInstance("destination-file", false)));

  @Override
  public String getName() {
    return COMMAND;
  }

  @Override
  public Collection<? extends Option> gatherOptions() {
    return ObjectUtils.notNull(List.of(
        MetaschemaCommands.OVERWRITE_OPTION,
        MetaschemaCommands.TO_OPTION));
  }

  @Override
  public List<ExtraArgument> getExtraArguments() {
    return EXTRA_ARGUMENTS;
  }

  /**
   * Used by implementing classes to provide for execution of a conversion
   * command.
   */
  protected abstract static class AbstractConversionCommandExecutor
      extends AbstractCommandExecutor {

    /**
     * Construct a new command executor.
     *
     * @param callingContext
     *          the context of the command execution
     * @param commandLine
     *          the parsed command line details
     */
    protected AbstractConversionCommandExecutor(
        @NonNull CallingContext callingContext,
        @NonNull CommandLine commandLine) {
      super(callingContext, commandLine);
    }

    /**
     * Get the binding context to use for data processing.
     *
     * @return the context
     * @throws CommandExecutionException
     *           if an error occurred getting the binding context
     * @throws MetaschemaException
     *           if an error occurred while setting up the binding context, such as
     *           pre-loading any needed modules
     */
    @NonNull
    protected abstract IBindingContext getBindingContext() throws CommandExecutionException, MetaschemaException;

    @SuppressWarnings({
        "PMD.CyclomaticComplexity" // reasonable
    })
    @Override
    public void execute() throws CommandExecutionException {
      CommandLine cmdLine = getCommandLine();

      List<String> extraArgs = cmdLine.getArgList();

      Path destination = null;
      if (extraArgs.size() > 1) {
        destination = MetaschemaCommands.handleDestination(ObjectUtils.requireNonNull(extraArgs.get(1)), cmdLine);
      }

      @SuppressWarnings("synthetic-access")
      URI source = MetaschemaCommands.handleSource(
          ObjectUtils.requireNonNull(extraArgs.get(0)),
          ObjectUtils.notNull(getCurrentWorkingDirectory().toUri()));

      Format toFormat = MetaschemaCommands.getFormat(cmdLine, MetaschemaCommands.TO_OPTION);

      try {
        IBindingContext bindingContext = getBindingContext();
        IBoundLoader loader = bindingContext.newBoundLoader();
        if (LOGGER.isInfoEnabled()) {
          LOGGER.info("Converting '{}'.", source);
        }

        if (destination == null) {
          // write to STDOUT
          try (OutputStreamWriter writer
              = new OutputStreamWriter(AutoCloser.preventClose(System.out), StandardCharsets.UTF_8)) {
            handleConversion(source, toFormat, writer, loader);
          }
        } else {
          try (Writer writer = Files.newBufferedWriter(
              destination,
              StandardCharsets.UTF_8,
              StandardOpenOption.CREATE,
              StandardOpenOption.WRITE,
              StandardOpenOption.TRUNCATE_EXISTING)) {
            assert writer != null;
            handleConversion(source, toFormat, writer, loader);
          }
        }
      } catch (IllegalArgumentException | MetaschemaException ex) {
        throw new CommandExecutionException(ExitCode.PROCESSING_ERROR, ex);
      } catch (IOException ex) {
        throw new CommandExecutionException(ExitCode.IO_ERROR, ex);
      }
      if (destination != null && LOGGER.isInfoEnabled()) {
        LOGGER.info("Generated {} file: {}", toFormat.toString(), destination);
      }
    }

    /**
     * Called to perform a content conversion.
     *
     * @param source
     *          the resource to convert
     * @param toFormat
     *          the format to convert to
     * @param writer
     *          the writer to use to write converted content
     * @param loader
     *          the Metaschema loader to use to load the content to convert
     * @throws FileNotFoundException
     *           if the requested resource was not found
     * @throws IOException
     *           if there was an error reading or writing content
     */
    protected abstract void handleConversion(
        @NonNull URI source,
        @NonNull Format toFormat,
        @NonNull Writer writer,
        @NonNull IBoundLoader loader) throws FileNotFoundException, IOException;
  }
}
