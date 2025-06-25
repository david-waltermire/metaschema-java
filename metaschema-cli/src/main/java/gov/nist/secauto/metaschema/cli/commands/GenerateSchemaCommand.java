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
import gov.nist.secauto.metaschema.core.configuration.DefaultConfiguration;
import gov.nist.secauto.metaschema.core.configuration.IMutableConfiguration;
import gov.nist.secauto.metaschema.core.model.IModule;
import gov.nist.secauto.metaschema.core.model.MetaschemaException;
import gov.nist.secauto.metaschema.core.util.AutoCloser;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.databind.IBindingContext;
import gov.nist.secauto.metaschema.schemagen.ISchemaGenerator;
import gov.nist.secauto.metaschema.schemagen.ISchemaGenerator.SchemaFormat;
import gov.nist.secauto.metaschema.schemagen.SchemaGenerationFeature;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Collection;
import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * This command implementation supports generation of schemas in a variety of
 * formats based on a provided Metaschema module.
 */
class GenerateSchemaCommand
    extends AbstractTerminalCommand {
  private static final Logger LOGGER = LogManager.getLogger(GenerateSchemaCommand.class);

  @NonNull
  private static final String COMMAND = "generate-schema";
  @NonNull
  private static final List<ExtraArgument> EXTRA_ARGUMENTS = ObjectUtils.notNull(List.of(
      ExtraArgument.newInstance("metaschema-module-file-or-URL", true),
      ExtraArgument.newInstance("destination-schema-file", false)));

  private static final Option INLINE_TYPES_OPTION = ObjectUtils.notNull(
      Option.builder()
          .longOpt("inline-types")
          .desc("definitions declared inline will be generated as inline types")
          .build());

  @Override
  public String getName() {
    return COMMAND;
  }

  @Override
  public String getDescription() {
    return "Generate a schema for the specified Module module";
  }

  @SuppressWarnings("null")
  @Override
  public Collection<? extends Option> gatherOptions() {
    return List.of(
        MetaschemaCommands.OVERWRITE_OPTION,
        MetaschemaCommands.AS_SCHEMA_FORMAT_OPTION,
        INLINE_TYPES_OPTION);
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
   * Execute the schema generation operation.
   *
   * @param callingContext
   *          the context information for the execution
   * @param cmdLine
   *          the parsed command line details
   * @throws CommandExecutionException
   *           if an error occurred while determining the source format
   */
  protected void executeCommand(
      @NonNull CallingContext callingContext,
      @NonNull CommandLine cmdLine) throws CommandExecutionException {
    List<String> extraArgs = cmdLine.getArgList();

    Path destination = extraArgs.size() > 1
        ? MetaschemaCommands.handleDestination(
            ObjectUtils.requireNonNull(extraArgs.get(1)),
            cmdLine)
        : null;

    SchemaFormat asFormat = MetaschemaCommands.getSchemaFormat(cmdLine, MetaschemaCommands.AS_SCHEMA_FORMAT_OPTION);

    IMutableConfiguration<SchemaGenerationFeature<?>> configuration = createConfiguration(cmdLine, asFormat);
    generateSchema(extraArgs, destination, asFormat, configuration);
  }

  @NonNull
  private static IMutableConfiguration<SchemaGenerationFeature<?>> createConfiguration(
      @NonNull CommandLine cmdLine,
      @NonNull SchemaFormat asFormat) {
    IMutableConfiguration<SchemaGenerationFeature<?>> configuration = new DefaultConfiguration<>();
    if (cmdLine.hasOption(INLINE_TYPES_OPTION)) {
      configuration.enableFeature(SchemaGenerationFeature.INLINE_DEFINITIONS);
      if (SchemaFormat.JSON.equals(asFormat)) {
        configuration.disableFeature(SchemaGenerationFeature.INLINE_CHOICE_DEFINITIONS);
      } else {
        configuration.enableFeature(SchemaGenerationFeature.INLINE_CHOICE_DEFINITIONS);
      }
    }
    return configuration;
  }

  private static void generateSchema(
      @NonNull List<String> extraArgs,
      @Nullable Path destination,
      @NonNull SchemaFormat asFormat,
      @NonNull IMutableConfiguration<SchemaGenerationFeature<?>> configuration) throws CommandExecutionException {
    IBindingContext bindingContext = MetaschemaCommands.newBindingContextWithDynamicCompilation();
    IModule module = MetaschemaCommands.loadModule(
        ObjectUtils.requireNonNull(extraArgs.get(0)),
        ObjectUtils.notNull(getCurrentWorkingDirectory().toUri()),
        bindingContext);

    try {
      bindingContext.registerModule(module);
      if (LOGGER.isInfoEnabled()) {
        LOGGER.info("Generating {} schema for '{}'.", asFormat.name(), extraArgs.get(0));
      }
      if (destination == null) {
        @SuppressWarnings({ "resource" }) // not owned
        OutputStream os = ObjectUtils.notNull(System.out);

        try (OutputStream out = AutoCloser.preventClose(os)) {
          try (OutputStreamWriter writer = new OutputStreamWriter(out, StandardCharsets.UTF_8)) {
            ISchemaGenerator.generateSchema(module, writer, asFormat, configuration);
          }
        }
      } else {
        ISchemaGenerator.generateSchema(module, destination, asFormat, configuration);
      }
    } catch (IOException | MetaschemaException ex) {
      throw new CommandExecutionException(ExitCode.PROCESSING_ERROR, ex);
    }
    if (destination != null && LOGGER.isInfoEnabled()) {
      LOGGER.info("Generated {} schema file: {}", asFormat.toString(), destination);
    }
  }
}
