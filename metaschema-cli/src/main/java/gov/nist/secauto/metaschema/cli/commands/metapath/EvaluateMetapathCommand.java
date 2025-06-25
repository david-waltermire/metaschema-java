/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.cli.commands.metapath;

import gov.nist.secauto.metaschema.cli.commands.MetaschemaCommands;
import gov.nist.secauto.metaschema.cli.processor.CLIProcessor.CallingContext;
import gov.nist.secauto.metaschema.cli.processor.ExitCode;
import gov.nist.secauto.metaschema.cli.processor.command.AbstractTerminalCommand;
import gov.nist.secauto.metaschema.cli.processor.command.CommandExecutionException;
import gov.nist.secauto.metaschema.cli.processor.command.ExtraArgument;
import gov.nist.secauto.metaschema.cli.processor.command.ICommandExecutor;
import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.IMetapathExpression;
import gov.nist.secauto.metaschema.core.metapath.StaticContext;
import gov.nist.secauto.metaschema.core.metapath.item.DefaultItemWriter;
import gov.nist.secauto.metaschema.core.metapath.item.IItemWriter;
import gov.nist.secauto.metaschema.core.metapath.item.ISequence;
import gov.nist.secauto.metaschema.core.metapath.item.node.INodeItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.INodeItemFactory;
import gov.nist.secauto.metaschema.core.model.IModule;
import gov.nist.secauto.metaschema.core.model.MetaschemaException;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.databind.IBindingContext;
import gov.nist.secauto.metaschema.databind.io.IBoundLoader;

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
import java.util.Collection;
import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

/**
 * This command implementation executes a Metapath query.
 * <p>
 * The query is executed using one of the following configurations:
 * <ol>
 * <li><b>module and content:</b> on a content instance parsed using a provided
 * Metaschema module,
 * <li><b>module-only:</b> against the Metaschema module itself if no content
 * instance is provided, or
 * <li><b>without content or module:</b> if both a module and content are
 * omitted then the execution will be limited to operations that do not act on
 * content.
 * </ol>
 */
class EvaluateMetapathCommand
    extends AbstractTerminalCommand {
  private static final Logger LOGGER = LogManager.getLogger(EvaluateMetapathCommand.class);

  @NonNull
  private static final String COMMAND = "eval";
  @NonNull
  private static final Option EXPRESSION_OPTION = ObjectUtils.notNull(
      Option.builder("e")
          .longOpt("expression")
          .required()
          .hasArg()
          .argName("EXPRESSION")
          .desc("Metapath expression to execute")
          .build());
  @NonNull
  private static final Option CONTENT_OPTION = ObjectUtils.notNull(
      Option.builder("i")
          .hasArg()
          .argName("FILE_OR_URL")
          .desc("Metaschema content instance resource")
          .build());

  @Override
  public String getName() {
    return COMMAND;
  }

  @Override
  public String getDescription() {
    return "Execute a Metapath expression against a document";
  }

  @SuppressWarnings("null")
  @Override
  public Collection<? extends Option> gatherOptions() {
    return List.of(
        MetaschemaCommands.METASCHEMA_OPTIONAL_OPTION,
        CONTENT_OPTION,
        EXPRESSION_OPTION);
  }

  @Override
  public List<ExtraArgument> getExtraArguments() {
    return CollectionUtil.emptyList();
  }

  @Override
  public ICommandExecutor newExecutor(CallingContext callingContext, CommandLine cmdLine) {
    return ICommandExecutor.using(callingContext, cmdLine, this::executeCommand);
  }

  @SuppressWarnings({
      "PMD.AvoidCatchingGenericException",
      "PMD.CognitiveComplexity",
      "PMD.CyclomaticComplexity"
  })
  @SuppressFBWarnings(value = "REC_CATCH_EXCEPTION",
      justification = "Catching generic exception for CLI error handling")
  private void executeCommand(
      @SuppressWarnings("unused") @NonNull CallingContext callingContext,
      @NonNull CommandLine cmdLine) throws CommandExecutionException {

    IModule module = null;
    INodeItem item = null;
    if (cmdLine.hasOption(MetaschemaCommands.METASCHEMA_OPTIONAL_OPTION)) {
      IBindingContext bindingContext = MetaschemaCommands.newBindingContextWithDynamicCompilation();

      try {
        module = bindingContext.registerModule(MetaschemaCommands.loadModule(
            cmdLine,
            MetaschemaCommands.METASCHEMA_OPTIONAL_OPTION,
            ObjectUtils.notNull(getCurrentWorkingDirectory().toUri()),
            bindingContext));
      } catch (MetaschemaException ex) {
        throw new CommandExecutionException(ExitCode.PROCESSING_ERROR, ex);
      }

      // determine if the query is evaluated against the module or the instance
      if (cmdLine.hasOption(CONTENT_OPTION)) {
        // load the content

        IBoundLoader loader = bindingContext.newBoundLoader();

        String contentLocation = ObjectUtils.requireNonNull(cmdLine.getOptionValue(CONTENT_OPTION));
        URI contentResource;
        try {
          contentResource = MetaschemaCommands.getResourceUri(
              contentLocation,
              ObjectUtils.notNull(getCurrentWorkingDirectory().toUri()));
        } catch (URISyntaxException ex) {
          throw new CommandExecutionException(
              ExitCode.INVALID_ARGUMENTS,
              String.format("Unable to load content '%s'. %s",
                  contentLocation,
                  ex.getMessage()),
              ex);
        }

        try {
          item = loader.loadAsNodeItem(contentResource);
        } catch (IOException ex) {
          throw new CommandExecutionException(
              ExitCode.INVALID_ARGUMENTS,
              String.format("Unable to load content '%s'. %s",
                  contentLocation,
                  ex.getMessage()),
              ex);
        }
      } else {
        // evaluate against the module
        item = INodeItemFactory.instance().newModuleNodeItem(module);
      }
    } else if (cmdLine.hasOption(CONTENT_OPTION)) {
      // content provided, but no module; require module
      throw new CommandExecutionException(
          ExitCode.INVALID_ARGUMENTS,
          String.format("Must use '%s' to specify the Metaschema module.",
              CONTENT_OPTION.getArgName()));
    }

    // now setup to evaluate the metapath
    StaticContext.Builder builder = StaticContext.builder();
    if (module != null) {
      builder.defaultModelNamespace(module.getXmlNamespace());
    }
    StaticContext staticContext = builder.build();

    String expression = cmdLine.getOptionValue(EXPRESSION_OPTION);
    if (expression == null) {
      throw new CommandExecutionException(
          ExitCode.INVALID_ARGUMENTS,
          String.format("Must use '%s' to specify the Metapath expression.", EXPRESSION_OPTION.getArgName()));
    }

    try {
      // Parse and compile the Metapath expression
      ISequence<?> sequence = IMetapathExpression.compile(expression, staticContext)
          .evaluate(item, new DynamicContext(staticContext));

      // handle the metapath results
      try (Writer stringWriter = new StringWriter()) {
        try (PrintWriter writer = new PrintWriter(stringWriter)) {
          try (IItemWriter itemWriter = new DefaultItemWriter(writer)) {
            itemWriter.writeSequence(sequence);
          } catch (IOException ex) {
            throw new CommandExecutionException(ExitCode.IO_ERROR, ex);
          } catch (Exception ex) {
            throw new CommandExecutionException(ExitCode.RUNTIME_ERROR, ex);
          }
        }

        // Print the result
        if (LOGGER.isInfoEnabled()) {
          LOGGER.info(stringWriter.toString());
        }
      } catch (IOException ex) {
        throw new CommandExecutionException(ExitCode.IO_ERROR, ex);
      }
    } catch (RuntimeException ex) {
      throw new CommandExecutionException(ExitCode.PROCESSING_ERROR, ex);
    }
  }
}
