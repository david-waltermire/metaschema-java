/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.cli.commands;

import gov.nist.secauto.metaschema.cli.processor.CLIProcessor.CallingContext;
import gov.nist.secauto.metaschema.cli.processor.ExitCode;
import gov.nist.secauto.metaschema.cli.processor.command.AbstractTerminalCommand;
import gov.nist.secauto.metaschema.cli.processor.command.CommandExecutionException;
import gov.nist.secauto.metaschema.cli.processor.command.ExtraArgument;
import gov.nist.secauto.metaschema.cli.processor.command.ICommandExecutor;
import gov.nist.secauto.metaschema.core.model.IModule;
import gov.nist.secauto.metaschema.core.model.util.MermaidErDiagramGenerator;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.databind.IBindingContext;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Collection;
import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

/**
 * This command implementation supports generation of a diagram depicting the
 * objects and relationships within a provided Metaschema module.
 */
class GenerateDiagramCommand
    extends AbstractTerminalCommand {
  private static final Logger LOGGER = LogManager.getLogger(GenerateDiagramCommand.class);

  @NonNull
  private static final String COMMAND = "generate-diagram";
  @NonNull
  private static final List<ExtraArgument> EXTRA_ARGUMENTS;

  static {
    EXTRA_ARGUMENTS = ObjectUtils.notNull(List.of(
        ExtraArgument.newInstance("metaschema-module-file-or-URL", true),
        ExtraArgument.newInstance("destination-diagram-file", false)));
  }

  @Override
  public String getName() {
    return COMMAND;
  }

  @Override
  public String getDescription() {
    return "Generate a diagram for the provided Metaschema module";
  }

  @SuppressWarnings("null")
  @Override
  public Collection<? extends Option> gatherOptions() {
    return List.of(MetaschemaCommands.OVERWRITE_OPTION);
  }

  @Override
  public List<ExtraArgument> getExtraArguments() {
    return EXTRA_ARGUMENTS;
  }

  @Override
  public ICommandExecutor newExecutor(CallingContext callingContext, CommandLine cmdLine) {
    return ICommandExecutor.using(callingContext, cmdLine, this::executeCommand);
  }

  /**
   * Execute the diagram generation command.
   *
   * @param callingContext
   *          information about the calling context
   * @param cmdLine
   *          the parsed command line details
   * @throws CommandExecutionException
   *           if an error occurred while executing the command
   */
  @SuppressFBWarnings(value = "REC_CATCH_EXCEPTION",
      justification = "Catching generic exception for CLI error handling")
  protected void executeCommand(
      @NonNull CallingContext callingContext,
      @NonNull CommandLine cmdLine) throws CommandExecutionException {

    List<String> extraArgs = cmdLine.getArgList();

    Path destination = null;
    if (extraArgs.size() > 1) {
      destination = MetaschemaCommands.handleDestination(ObjectUtils.requireNonNull(extraArgs.get(1)), cmdLine);
    }

    IBindingContext bindingContext = MetaschemaCommands.newBindingContextWithDynamicCompilation();

    URI moduleUri;
    try {
      moduleUri = resolveAgainstCWD(ObjectUtils.requireNonNull(extraArgs.get(0)));
    } catch (URISyntaxException ex) {
      throw new CommandExecutionException(
          ExitCode.INVALID_ARGUMENTS,
          String.format("Cannot load module as '%s' is not a valid file or URL. %s",
              extraArgs.get(0),
              ex.getLocalizedMessage()),
          ex);
    }
    IModule module = MetaschemaCommands.loadModule(moduleUri, bindingContext);

    if (destination == null) {
      Writer stringWriter = new StringWriter();
      try (PrintWriter writer = new PrintWriter(stringWriter)) {
        MermaidErDiagramGenerator.generate(module, writer);
      }

      // Print the result
      if (LOGGER.isInfoEnabled()) {
        LOGGER.info(stringWriter.toString());
      }
    } else {
      try (Writer writer = Files.newBufferedWriter(
          destination,
          StandardCharsets.UTF_8,
          StandardOpenOption.CREATE,
          StandardOpenOption.WRITE,
          StandardOpenOption.TRUNCATE_EXISTING)) {
        try (PrintWriter printWriter = new PrintWriter(writer)) {
          MermaidErDiagramGenerator.generate(module, printWriter);
        }
      } catch (IOException ex) {
        throw new CommandExecutionException(ExitCode.IO_ERROR, ex);
      }
    }
  }
}
