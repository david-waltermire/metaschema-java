/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.cli.commands;

import gov.nist.secauto.metaschema.cli.commands.metapath.MetapathCommand;
import gov.nist.secauto.metaschema.cli.processor.ExitCode;
import gov.nist.secauto.metaschema.cli.processor.OptionUtils;
import gov.nist.secauto.metaschema.cli.processor.command.CommandExecutionException;
import gov.nist.secauto.metaschema.cli.processor.command.ICommand;
import gov.nist.secauto.metaschema.core.metapath.MetapathException;
import gov.nist.secauto.metaschema.core.model.IConstraintLoader;
import gov.nist.secauto.metaschema.core.model.IModule;
import gov.nist.secauto.metaschema.core.model.MetaschemaException;
import gov.nist.secauto.metaschema.core.model.constraint.IConstraintSet;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;
import gov.nist.secauto.metaschema.core.util.CustomCollectors;
import gov.nist.secauto.metaschema.core.util.DeleteOnShutdown;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.core.util.UriUtils;
import gov.nist.secauto.metaschema.databind.IBindingContext;
import gov.nist.secauto.metaschema.databind.io.Format;
import gov.nist.secauto.metaschema.databind.io.IBoundLoader;
import gov.nist.secauto.metaschema.databind.model.metaschema.IBindingModuleLoader;
import gov.nist.secauto.metaschema.schemagen.ISchemaGenerator.SchemaFormat;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * This class provides a variety of utility methods for processing
 * Metaschema-related commands.
 * <p>
 * These methods handle the errors produced using the
 * {@link CommandExecutionException}, which will return an exceptional result to
 * the command line interface (CLI) processor. This approach keeps the command
 * implementations fairly clean and simple.
 */
@SuppressWarnings("PMD.GodClass")
public final class MetaschemaCommands {
  /**
   * A list of the Metaschema-related command pathways, for reuse in this and
   * other CLI applications.
   */
  @NonNull
  public static final List<ICommand> COMMANDS = ObjectUtils.notNull(List.of(
      new ValidateModuleCommand(),
      new GenerateSchemaCommand(),
      new GenerateDiagramCommand(),
      new ValidateContentUsingModuleCommand(),
      new ConvertContentUsingModuleCommand(),
      new MetapathCommand()));

  /**
   * Used by commands to declare a required Metaschema module for processing.
   *
   * @since 2.0.0
   */
  @NonNull
  public static final Option METASCHEMA_REQUIRED_OPTION = ObjectUtils.notNull(
      Option.builder("m")
          .hasArg()
          .argName("FILE_OR_URL")
          .required()
          .desc("metaschema resource")
          .numberOfArgs(1)
          .build());
  /**
   * Used by commands to declare an optional Metaschema module for processing.
   *
   * @since 2.0.0
   */
  @NonNull
  public static final Option METASCHEMA_OPTIONAL_OPTION = ObjectUtils.notNull(
      Option.builder("m")
          .hasArg()
          .argName("FILE_OR_URL")
          .desc("metaschema resource")
          .numberOfArgs(1)
          .build());
  /**
   * Used by commands to protect existing files from being overwritten, unless
   * this option is provided.
   */
  @NonNull
  public static final Option OVERWRITE_OPTION = ObjectUtils.notNull(
      Option.builder()
          .longOpt("overwrite")
          .desc("overwrite the destination if it exists")
          .build());
  /**
   * Used by commands to identify the target format for a content conversion
   * operation.
   *
   * @since 2.0.0
   */
  @NonNull
  public static final Option TO_OPTION = ObjectUtils.notNull(
      Option.builder()
          .longOpt("to")
          .required()
          .hasArg().argName("FORMAT")
          .desc("convert to format: " + Arrays.stream(Format.values())
              .map(Enum::name)
              .collect(CustomCollectors.joiningWithOxfordComma("or")))
          .numberOfArgs(1)
          .build());
  /**
   * Used by commands to identify the source format for a content-related
   * operation.
   *
   * @since 2.0.0
   */
  @NonNull
  public static final Option AS_FORMAT_OPTION = ObjectUtils.notNull(
      Option.builder()
          .longOpt("as")
          .hasArg()
          .argName("FORMAT")
          .desc("source format: " + Arrays.stream(Format.values())
              .map(Enum::name)
              .collect(CustomCollectors.joiningWithOxfordComma("or")))
          .numberOfArgs(1)
          .build());
  /**
   * Used by commands that produce schemas to identify the schema format to
   * produce.
   *
   * @since 2.0.0
   */
  @NonNull
  public static final Option AS_SCHEMA_FORMAT_OPTION = ObjectUtils.notNull(
      Option.builder()
          .longOpt("as")
          .required()
          .hasArg()
          .argName("FORMAT")
          .desc("schema format: " + Arrays.stream(SchemaFormat.values())
              .map(Enum::name)
              .collect(CustomCollectors.joiningWithOxfordComma("or")))
          .numberOfArgs(1)
          .build());

  /**
   * Get the provided source path or URI string as an absolute {@link URI} for the
   * resource.
   *
   * @param pathOrUri
   *          the resource
   * @param currentWorkingDirectory
   *          the current working directory the URI will be resolved against to
   *          ensure it is absolute
   * @return the absolute URI for the resource
   * @throws CommandExecutionException
   *           if the resulting URI is not a well-formed URI
   * @since 2.0.0
   */
  @NonNull
  public static URI handleSource(
      @NonNull String pathOrUri,
      @NonNull URI currentWorkingDirectory) throws CommandExecutionException {
    try {
      return getResourceUri(pathOrUri, currentWorkingDirectory);
    } catch (URISyntaxException ex) {
      throw new CommandExecutionException(
          ExitCode.INVALID_ARGUMENTS,
          String.format(
              "Cannot load source '%s' as it is not a valid file or URI.",
              pathOrUri),
          ex);
    }
  }

  /**
   * Get the provided destination path as an absolute {@link Path} for the
   * resource.
   * <p>
   * This method checks if the path exists and if so, if the overwrite option is
   * set. The method also ensures that the parent directory is created, if it
   * doesn't already exist.
   *
   * @param path
   *          the resource
   * @param commandLine
   *          the provided command line argument information
   * @return the absolute URI for the resource
   * @throws CommandExecutionException
   *           if the path exists and cannot be overwritten or is not writable
   * @since 2.0.0
   */
  public static Path handleDestination(
      @NonNull String path,
      @NonNull CommandLine commandLine) throws CommandExecutionException {
    Path retval = Paths.get(path).toAbsolutePath();

    if (Files.exists(retval)) {
      if (!commandLine.hasOption(OVERWRITE_OPTION)) {
        throw new CommandExecutionException(
            ExitCode.INVALID_ARGUMENTS,
            String.format("The provided destination '%s' already exists and the '%s' option was not provided.",
                retval,
                OptionUtils.toArgument(OVERWRITE_OPTION)));
      }
      if (!Files.isWritable(retval)) {
        throw new CommandExecutionException(
            ExitCode.IO_ERROR,
            String.format(
                "The provided destination '%s' is not writable.", retval));
      }
    } else {
      Path parent = retval.getParent();
      if (parent != null) {
        try {
          Files.createDirectories(parent);
        } catch (IOException ex) {
          throw new CommandExecutionException(
              ExitCode.INVALID_TARGET,
              ex);
        }
      }
    }
    return retval;
  }

  /**
   * Parse the command line options to get the selected format.
   *
   * @param commandLine
   *          the provided command line argument information
   * @param option
   *          the option specifying the format, which must be present on the
   *          command line
   * @return the format
   * @throws CommandExecutionException
   *           if the format option was not provided or was an invalid choice
   * @since 2.0.0
   */
  @NonNull
  public static Format getFormat(
      @NonNull CommandLine commandLine,
      @NonNull Option option) throws CommandExecutionException {
    // use the option
    String toFormatText = commandLine.getOptionValue(option);
    if (toFormatText == null) {
      throw new CommandExecutionException(
          ExitCode.INVALID_ARGUMENTS,
          String.format("The '%s' argument was not provided.",
              option.hasLongOpt()
                  ? "--" + option.getLongOpt()
                  : "-" + option.getOpt()));
    }
    try {
      return Format.valueOf(toFormatText.toUpperCase(Locale.ROOT));
    } catch (IllegalArgumentException ex) {
      throw new CommandExecutionException(
          ExitCode.INVALID_ARGUMENTS,
          String.format("Invalid '%s' argument. The format must be one of: %s.",
              option.hasLongOpt()
                  ? "--" + option.getLongOpt()
                  : "-" + option.getOpt(),
              Arrays.stream(Format.values())
                  .map(Enum::name)
                  .collect(CustomCollectors.joiningWithOxfordComma("or"))),
          ex);
    }
  }

  /**
   * Parse the command line options to get the selected schema format.
   *
   * @param commandLine
   *          the provided command line argument information
   * @param option
   *          the option specifying the format, which must be present on the
   *          command line
   * @return the format
   * @throws CommandExecutionException
   *           if the format option was not provided or was an invalid choice
   * @since 2.0.0
   */
  @NonNull
  public static SchemaFormat getSchemaFormat(
      @NonNull CommandLine commandLine,
      @NonNull Option option) throws CommandExecutionException {
    // use the option
    String toFormatText = commandLine.getOptionValue(option);
    if (toFormatText == null) {
      throw new CommandExecutionException(
          ExitCode.INVALID_ARGUMENTS,
          String.format("Option '%s' not provided.",
              option.hasLongOpt()
                  ? "--" + option.getLongOpt()
                  : "-" + option.getOpt()));
    }
    try {
      return SchemaFormat.valueOf(toFormatText.toUpperCase(Locale.ROOT));
    } catch (IllegalArgumentException ex) {
      throw new CommandExecutionException(
          ExitCode.INVALID_ARGUMENTS,
          String.format("Invalid '%s' argument. The schema format must be one of: %s.",
              option.hasLongOpt()
                  ? "--" + option.getLongOpt()
                  : "-" + option.getOpt(),
              Arrays.stream(SchemaFormat.values())
                  .map(Enum::name)
                  .collect(CustomCollectors.joiningWithOxfordComma("or"))),
          ex);
    }
  }

  /**
   * Detect the source format for content identified using the provided option.
   * <p>
   * This method will first check if the source format is explicitly declared on
   * the command line. If so, this format will be returned.
   * <p>
   * If not, then the content will be analyzed to determine the format.
   *
   * @param commandLine
   *          the provided command line argument information
   * @param option
   *          the option specifying the format, which must be present on the
   *          command line
   * @param loader
   *          the content loader to use to load the content instance
   * @param resource
   *          the resource to load
   * @return the identified content format
   * @throws CommandExecutionException
   *           if an error occurred while determining the source format
   * @since 2.0.0
   */
  @SuppressWarnings("PMD.OnlyOneReturn")
  @NonNull
  public static Format determineSourceFormat(
      @NonNull CommandLine commandLine,
      @NonNull Option option,
      @NonNull IBoundLoader loader,
      @NonNull URI resource) throws CommandExecutionException {
    if (commandLine.hasOption(option)) {
      // use the option
      return getFormat(commandLine, option);
    }

    // attempt to determine the format
    try {
      return loader.detectFormat(resource);
    } catch (FileNotFoundException ex) {
      // this case was already checked for
      throw new CommandExecutionException(
          ExitCode.IO_ERROR,
          String.format("The provided source '%s' does not exist.", resource),
          ex);
    } catch (IOException ex) {
      throw new CommandExecutionException(
          ExitCode.IO_ERROR,
          String.format("Unable to determine source format. Use '%s' to specify the format. %s",
              option.hasLongOpt()
                  ? "--" + option.getLongOpt()
                  : "-" + option.getOpt(),
              ex.getLocalizedMessage()),
          ex);
    }
  }

  /**
   * Load a Metaschema module based on the provided command line option.
   *
   * @param commandLine
   *          the provided command line argument information
   * @param option
   *          the option specifying the module to load, which must be present on
   *          the command line
   * @param currentWorkingDirectory
   *          the URI of the current working directory
   * @param bindingContext
   *          the context used to access Metaschema module information based on
   *          Java class bindings
   * @return the loaded module
   * @throws CommandExecutionException
   *           if an error occurred while loading the module
   * @since 2.0.0
   */
  @NonNull
  public static IModule loadModule(
      @NonNull CommandLine commandLine,
      @NonNull Option option,
      @NonNull URI currentWorkingDirectory,
      @NonNull IBindingContext bindingContext) throws CommandExecutionException {
    String moduleName = commandLine.getOptionValue(option);
    if (moduleName == null) {
      throw new CommandExecutionException(
          ExitCode.INVALID_ARGUMENTS,
          String.format("Unable to determine the module to load. Use '%s' to specify the module.",
              option.hasLongOpt()
                  ? "--" + option.getLongOpt()
                  : "-" + option.getOpt()));
    }

    URI moduleUri;
    try {
      moduleUri = UriUtils.toUri(moduleName, currentWorkingDirectory);
    } catch (URISyntaxException ex) {
      throw new CommandExecutionException(
          ExitCode.INVALID_ARGUMENTS,
          String.format("Cannot load module as '%s' is not a valid file or URL. %s",
              ex.getInput(),
              ex.getLocalizedMessage()),
          ex);
    }
    return loadModule(moduleUri, bindingContext);
  }

  /**
   * Load a Metaschema module from the provided relative resource path.
   * <p>
   * This method will resolve the provided resource against the current working
   * directory to create an absolute URI.
   *
   * @param moduleResource
   *          the relative path to the module resource to load
   * @param currentWorkingDirectory
   *          the URI of the current working directory
   * @param bindingContext
   *          the context used to access Metaschema module information based on
   *          Java class bindings
   * @return the loaded module
   * @throws CommandExecutionException
   *           if an error occurred while loading the module
   * @since 2.0.0
   */
  @NonNull
  public static IModule loadModule(
      @NonNull String moduleResource,
      @NonNull URI currentWorkingDirectory,
      @NonNull IBindingContext bindingContext) throws CommandExecutionException {
    try {
      URI moduleUri = getResourceUri(
          moduleResource,
          currentWorkingDirectory);
      return loadModule(moduleUri, bindingContext);
    } catch (URISyntaxException ex) {
      throw new CommandExecutionException(
          ExitCode.INVALID_ARGUMENTS,
          String.format("Cannot load module as '%s' is not a valid file or URL. %s",
              ex.getInput(),
              ex.getLocalizedMessage()),
          ex);
    }
  }

  /**
   * Load a Metaschema module from the provided resource path.
   *
   * @param moduleResource
   *          the absolute path to the module resource to load
   * @param bindingContext
   *          the context used to access Metaschema module information based on
   *          Java class bindings
   * @return the loaded module
   * @throws CommandExecutionException
   *           if an error occurred while loading the module
   * @since 2.0.0
   */
  @NonNull
  public static IModule loadModule(
      @NonNull URI moduleResource,
      @NonNull IBindingContext bindingContext) throws CommandExecutionException {
    // TODO: ensure the resource URI is absolute
    try {
      IBindingModuleLoader loader = bindingContext.newModuleLoader();
      loader.allowEntityResolution();
      return loader.load(moduleResource);
    } catch (IOException | MetaschemaException ex) {
      throw new CommandExecutionException(ExitCode.PROCESSING_ERROR, ex);
    }
  }

  /**
   * For a given resource location, resolve the location into an absolute URI.
   *
   * @param location
   *          the resource location
   * @param currentWorkingDirectory
   *          the URI of the current working directory
   * @return the resolved URI
   * @throws URISyntaxException
   *           if the location is not a valid URI
   */
  @NonNull
  public static URI getResourceUri(
      @NonNull String location,
      @NonNull URI currentWorkingDirectory) throws URISyntaxException {
    return UriUtils.toUri(location, currentWorkingDirectory);
  }

  /**
   * Load a set of external Metaschema module constraints based on the provided
   * command line option.
   *
   * @param commandLine
   *          the provided command line argument information
   * @param option
   *          the option specifying the constraints to load, which must be present
   *          on the command line
   * @param currentWorkingDirectory
   *          the URI of the current working directory
   * @return the set of loaded constraints
   * @throws CommandExecutionException
   *           if an error occurred while loading the module
   * @since 2.0.0
   */
  @NonNull
  public static Set<IConstraintSet> loadConstraintSets(
      @NonNull CommandLine commandLine,
      @NonNull Option option,
      @NonNull URI currentWorkingDirectory) throws CommandExecutionException {
    Set<IConstraintSet> constraintSets;
    if (commandLine.hasOption(option)) {
      IConstraintLoader constraintLoader = IBindingContext.getConstraintLoader();
      constraintSets = new LinkedHashSet<>();
      String[] args = commandLine.getOptionValues(option);
      for (String arg : args) {
        assert arg != null;
        try {
          URI constraintUri = ObjectUtils.requireNonNull(UriUtils.toUri(arg, currentWorkingDirectory));
          constraintSets.addAll(constraintLoader.load(constraintUri));
        } catch (URISyntaxException | IOException | MetaschemaException | MetapathException ex) {
          throw new CommandExecutionException(
              ExitCode.IO_ERROR,
              String.format("Unable to process constraint set '%s'. %s",
                  arg,
                  ex.getLocalizedMessage()),
              ex);
        }
      }
    } else {
      constraintSets = CollectionUtil.emptySet();
    }
    return constraintSets;
  }

  /**
   * Create a temporary directory for ephemeral files that will be deleted on
   * shutdown.
   *
   * @return the temp directory path
   * @throws IOException
   *           if an error occurred while creating the temporary directory
   */
  @NonNull
  public static Path newTempDir() throws IOException {
    Path retval = Files.createTempDirectory("metaschema-cli-");
    DeleteOnShutdown.register(retval);
    return ObjectUtils.notNull(retval);
  }

  /**
   * Create a new {@link IBindingContext} that is configured for dynamic
   * compilation.
   *
   * @return the binding context
   * @throws CommandExecutionException
   *           if an error occurred while creating the binding context
   * @since 2.0.0
   */
  @NonNull
  public static IBindingContext newBindingContextWithDynamicCompilation() throws CommandExecutionException {
    return newBindingContextWithDynamicCompilation(CollectionUtil.emptySet());
  }

  /**
   * Create a new {@link IBindingContext} that is configured for dynamic
   * compilation and to use the provided constraints.
   *
   * @param constraintSets
   *          the Metaschema module constraints to dynamicly bind to loaded
   *          modules
   * @return the binding context
   * @throws CommandExecutionException
   *           if an error occurred while creating the binding context
   * @since 2.0.0
   */
  @NonNull
  public static IBindingContext newBindingContextWithDynamicCompilation(@NonNull Set<IConstraintSet> constraintSets)
      throws CommandExecutionException {
    try {
      Path tempDir = newTempDir();
      return IBindingContext.builder()
          .compilePath(tempDir)
          .constraintSet(constraintSets)
          .build();
    } catch (IOException ex) {
      throw new CommandExecutionException(ExitCode.RUNTIME_ERROR,
          String.format("Unable to initialize the binding context. %s", ex.getLocalizedMessage()),
          ex);
    }
  }

  private MetaschemaCommands() {
    // disable construction
  }
}
