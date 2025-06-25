/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.cli.commands;

import gov.nist.secauto.metaschema.cli.processor.CLIProcessor;
import gov.nist.secauto.metaschema.cli.processor.CLIProcessor.CallingContext;
import gov.nist.secauto.metaschema.cli.processor.ExitCode;
import gov.nist.secauto.metaschema.cli.processor.command.AbstractCommandExecutor;
import gov.nist.secauto.metaschema.cli.processor.command.AbstractTerminalCommand;
import gov.nist.secauto.metaschema.cli.processor.command.CommandExecutionException;
import gov.nist.secauto.metaschema.cli.processor.command.ExtraArgument;
import gov.nist.secauto.metaschema.cli.util.LoggingValidationHandler;
import gov.nist.secauto.metaschema.core.configuration.DefaultConfiguration;
import gov.nist.secauto.metaschema.core.configuration.IMutableConfiguration;
import gov.nist.secauto.metaschema.core.metapath.MetapathException;
import gov.nist.secauto.metaschema.core.model.IModule;
import gov.nist.secauto.metaschema.core.model.MetaschemaException;
import gov.nist.secauto.metaschema.core.model.constraint.ConstraintValidationException;
import gov.nist.secauto.metaschema.core.model.constraint.IConstraintSet;
import gov.nist.secauto.metaschema.core.model.constraint.ValidationFeature;
import gov.nist.secauto.metaschema.core.model.validation.AggregateValidationResult;
import gov.nist.secauto.metaschema.core.model.validation.IValidationResult;
import gov.nist.secauto.metaschema.core.util.IVersionInfo;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.databind.IBindingContext;
import gov.nist.secauto.metaschema.databind.IBindingContext.ISchemaValidationProvider;
import gov.nist.secauto.metaschema.databind.io.Format;
import gov.nist.secauto.metaschema.databind.io.IBoundLoader;
import gov.nist.secauto.metaschema.modules.sarif.SarifValidationHandler;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collection;
import java.util.List;
import java.util.Set;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Used by implementing classes to provide a content validation command.
 */
public abstract class AbstractValidateContentCommand
    extends AbstractTerminalCommand {
  private static final Logger LOGGER = LogManager.getLogger(AbstractValidateContentCommand.class);
  @NonNull
  private static final String COMMAND = "validate";
  @NonNull
  private static final List<ExtraArgument> EXTRA_ARGUMENTS = ObjectUtils.notNull(List.of(
      ExtraArgument.newInstance("file-or-URI-to-validate", true)));

  @NonNull
  private static final Option CONSTRAINTS_OPTION = ObjectUtils.notNull(
      Option.builder("c")
          .hasArgs()
          .argName("URL")
          .desc("additional constraint definitions")
          .build());
  @NonNull
  private static final Option SARIF_OUTPUT_FILE_OPTION = ObjectUtils.notNull(
      Option.builder("o")
          .hasArg()
          .argName("FILE")
          .desc("write SARIF results to the provided FILE")
          .numberOfArgs(1)
          .build());
  @NonNull
  private static final Option SARIF_INCLUDE_PASS_OPTION = ObjectUtils.notNull(
      Option.builder()
          .longOpt("sarif-include-pass")
          .desc("include pass results in SARIF")
          .build());
  @NonNull
  private static final Option NO_SCHEMA_VALIDATION_OPTION = ObjectUtils.notNull(
      Option.builder()
          .longOpt("disable-schema-validation")
          .desc("do not perform schema validation")
          .build());
  @NonNull
  private static final Option NO_CONSTRAINT_VALIDATION_OPTION = ObjectUtils.notNull(
      Option.builder()
          .longOpt("disable-constraint-validation")
          .desc("do not perform constraint validation")
          .build());

  @Override
  public String getName() {
    return COMMAND;
  }

  @SuppressWarnings("null")
  @Override
  public Collection<? extends Option> gatherOptions() {
    return List.of(
        MetaschemaCommands.AS_FORMAT_OPTION,
        CONSTRAINTS_OPTION,
        SARIF_OUTPUT_FILE_OPTION,
        SARIF_INCLUDE_PASS_OPTION,
        NO_SCHEMA_VALIDATION_OPTION,
        NO_CONSTRAINT_VALIDATION_OPTION);
  }

  @Override
  public List<ExtraArgument> getExtraArguments() {
    return EXTRA_ARGUMENTS;
  }

  /**
   * Drives the validation execution.
   */
  protected abstract class AbstractValidationCommandExecutor
      extends AbstractCommandExecutor {

    /**
     * Construct a new command executor.
     *
     * @param callingContext
     *          the context of the command execution
     * @param commandLine
     *          the parsed command line details
     */
    public AbstractValidationCommandExecutor(
        @NonNull CallingContext callingContext,
        @NonNull CommandLine commandLine) {
      super(callingContext, commandLine);
    }

    /**
     * Get the binding context to use for data processing.
     *
     * @param constraintSets
     *          the constraints to configure in the resulting binding context
     * @return the context
     * @throws CommandExecutionException
     *           if a error occurred while getting the binding context
     */
    @NonNull
    protected abstract IBindingContext getBindingContext(@NonNull Set<IConstraintSet> constraintSets)
        throws CommandExecutionException;

    /**
     * Get the module to use for validation.
     * <p>
     * This module is used to generate schemas and as a source of built-in
     * constraints.
     *
     * @param commandLine
     *          the provided command line argument information
     * @param bindingContext
     *          the context used to access Metaschema module information based on
     *          Java class bindings
     * @return the loaded Metaschema module
     * @throws CommandExecutionException
     *           if an error occurred while loading the module
     */
    @NonNull
    protected abstract IModule getModule(
        @NonNull CommandLine commandLine,
        @NonNull IBindingContext bindingContext)
        throws CommandExecutionException;

    /**
     * Get the schema validation implementation requested based on the provided
     * command line arguments.
     * <p>
     * It is typical for this call to result in the dynamic generation of a schema
     * to use for validation.
     *
     * @param module
     *          the Metaschema module to generate the schema from
     * @param commandLine
     *          the provided command line argument information
     * @param bindingContext
     *          the context used to access Metaschema module information based on
     *          Java class bindings
     * @return the provider
     */
    @NonNull
    protected abstract ISchemaValidationProvider getSchemaValidationProvider(
        @NonNull IModule module,
        @NonNull CommandLine commandLine,
        @NonNull IBindingContext bindingContext);

    /**
     * Execute the validation operation.
     */
    @Override
    public void execute() throws CommandExecutionException {
      CommandLine cmdLine = getCommandLine();
      @SuppressWarnings("synthetic-access")
      URI currentWorkingDirectory = ObjectUtils.notNull(getCurrentWorkingDirectory().toUri());

      Set<IConstraintSet> constraintSets = MetaschemaCommands.loadConstraintSets(
          cmdLine,
          CONSTRAINTS_OPTION,
          currentWorkingDirectory);

      List<String> extraArgs = cmdLine.getArgList();

      URI source = MetaschemaCommands.handleSource(
          ObjectUtils.requireNonNull(extraArgs.get(0)),
          currentWorkingDirectory);

      IBindingContext bindingContext = getBindingContext(constraintSets);
      IBoundLoader loader = bindingContext.newBoundLoader();
      Format asFormat = MetaschemaCommands.determineSourceFormat(
          cmdLine,
          MetaschemaCommands.AS_FORMAT_OPTION,
          loader,
          source);

      IValidationResult validationResult = validate(source, asFormat, cmdLine, bindingContext);
      handleOutput(source, validationResult, cmdLine, bindingContext);

      if (validationResult == null || validationResult.isPassing()) {
        if (LOGGER.isInfoEnabled()) {
          LOGGER.info("The file '{}' is valid.", source);
        }
      } else if (LOGGER.isErrorEnabled()) {
        LOGGER.error("The file '{}' is invalid.", source);
      }

      if (validationResult != null && !validationResult.isPassing()) {
        throw new CommandExecutionException(ExitCode.FAIL);
      }
    }

    @SuppressWarnings("PMD.CyclomaticComplexity")
    @Nullable
    private IValidationResult validate(
        @NonNull URI source,
        @NonNull Format asFormat,
        @NonNull CommandLine commandLine,
        @NonNull IBindingContext bindingContext) throws CommandExecutionException {

      if (LOGGER.isInfoEnabled()) {
        LOGGER.info("Validating '{}' as {}.", source, asFormat.name());
      }

      IValidationResult validationResult = null;
      try {
        // get the module, but don't register it
        IModule module = getModule(commandLine, bindingContext);
        if (!commandLine.hasOption(NO_SCHEMA_VALIDATION_OPTION)) {
          // perform schema validation
          validationResult = getSchemaValidationProvider(module, commandLine, bindingContext)
              .validateWithSchema(source, asFormat, bindingContext);
        }

        if (!commandLine.hasOption(NO_CONSTRAINT_VALIDATION_OPTION)) {
          IMutableConfiguration<ValidationFeature<?>> configuration = new DefaultConfiguration<>();
          if (commandLine.hasOption(SARIF_OUTPUT_FILE_OPTION) && commandLine.hasOption(SARIF_INCLUDE_PASS_OPTION)) {
            configuration.enableFeature(ValidationFeature.VALIDATE_GENERATE_PASS_FINDINGS);
          }

          // perform constraint validation
          bindingContext.registerModule(module); // ensure the module is registered
          IValidationResult constraintValidationResult = bindingContext.validateWithConstraints(source, configuration);
          validationResult = validationResult == null
              ? constraintValidationResult
              : AggregateValidationResult.aggregate(validationResult, constraintValidationResult);
        }
      } catch (FileNotFoundException ex) {
        throw new CommandExecutionException(
            ExitCode.IO_ERROR,
            String.format("Resource not found at '%s'", source),
            ex);
      } catch (UnknownHostException ex) {
        throw new CommandExecutionException(
            ExitCode.IO_ERROR,
            String.format("Unknown host for '%s'.", source),
            ex);
      } catch (IOException ex) {
        throw new CommandExecutionException(ExitCode.IO_ERROR, ex.getLocalizedMessage(), ex);
      } catch (MetapathException | MetaschemaException | ConstraintValidationException ex) {
        throw new CommandExecutionException(ExitCode.PROCESSING_ERROR, ex.getLocalizedMessage(), ex);
      }
      return validationResult;
    }

    private void handleOutput(
        @NonNull URI source,
        @Nullable IValidationResult validationResult,
        @NonNull CommandLine commandLine,
        @NonNull IBindingContext bindingContext) throws CommandExecutionException {
      if (commandLine.hasOption(SARIF_OUTPUT_FILE_OPTION)) {
        Path sarifFile = ObjectUtils.notNull(Paths.get(commandLine.getOptionValue(SARIF_OUTPUT_FILE_OPTION)));

        IVersionInfo version
            = getCallingContext().getCLIProcessor().getVersionInfos().get(CLIProcessor.COMMAND_VERSION);

        try {
          SarifValidationHandler sarifHandler = new SarifValidationHandler(source, version);
          if (validationResult != null) {
            sarifHandler.addFindings(validationResult.getFindings());
          }
          sarifHandler.write(sarifFile, bindingContext);
        } catch (IOException ex) {
          throw new CommandExecutionException(ExitCode.IO_ERROR, ex.getLocalizedMessage(), ex);
        }
      } else if (validationResult != null && !validationResult.getFindings().isEmpty()) {
        LOGGER.info("Validation identified the following issues:");
        LoggingValidationHandler.instance().handleResults(validationResult);
      }

    }
  }
}
