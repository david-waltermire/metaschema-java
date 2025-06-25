/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.cli.processor;

import static org.fusesource.jansi.Ansi.ansi;

import gov.nist.secauto.metaschema.cli.processor.command.CommandExecutionException;
import gov.nist.secauto.metaschema.cli.processor.command.CommandService;
import gov.nist.secauto.metaschema.cli.processor.command.ExtraArgument;
import gov.nist.secauto.metaschema.cli.processor.command.ICommand;
import gov.nist.secauto.metaschema.cli.processor.command.ICommandExecutor;
import gov.nist.secauto.metaschema.core.util.AutoCloser;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;
import gov.nist.secauto.metaschema.core.util.IVersionInfo;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.fusesource.jansi.AnsiConsole;
import org.fusesource.jansi.AnsiPrintStream;

import java.io.PrintStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import java.util.stream.Collectors;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

/**
 * Processes command line arguments and dispatches called commands.
 * <p>
 * This implementation make significant use of the command pattern to support a
 * delegation chain of commands based on implementations of {@link ICommand}.
 */
@SuppressWarnings("PMD.CouplingBetweenObjects")
public class CLIProcessor {
  private static final Logger LOGGER = LogManager.getLogger(CLIProcessor.class);

  /**
   * This option indicates if the help should be shown.
   */
  @NonNull
  public static final Option HELP_OPTION = ObjectUtils.notNull(Option.builder("h")
      .longOpt("help")
      .desc("display this help message")
      .build());
  /**
   * This option indicates if colorized output should be disabled.
   */
  @NonNull
  public static final Option NO_COLOR_OPTION = ObjectUtils.notNull(Option.builder()
      .longOpt("no-color")
      .desc("do not colorize output")
      .build());
  /**
   * This option indicates if non-errors should be suppressed.
   */
  @NonNull
  public static final Option QUIET_OPTION = ObjectUtils.notNull(Option.builder("q")
      .longOpt("quiet")
      .desc("minimize output to include only errors")
      .build());
  /**
   * This option indicates if a strack trace should be shown for an error
   * {@link ExitStatus}.
   */
  @NonNull
  public static final Option SHOW_STACK_TRACE_OPTION = ObjectUtils.notNull(Option.builder()
      .longOpt("show-stack-trace")
      .desc("display the stack trace associated with an error")
      .build());
  /**
   * This option indicates if the version information should be shown.
   */
  @NonNull
  public static final Option VERSION_OPTION = ObjectUtils.notNull(Option.builder()
      .longOpt("version")
      .desc("display the application version")
      .build());

  @NonNull
  private static final List<Option> OPTIONS = ObjectUtils.notNull(List.of(
      HELP_OPTION,
      NO_COLOR_OPTION,
      QUIET_OPTION,
      SHOW_STACK_TRACE_OPTION,
      VERSION_OPTION));

  /**
   * Used to identify the version info for the command.
   */
  public static final String COMMAND_VERSION = "http://csrc.nist.gov/ns/metaschema-java/cli/command-version";

  @NonNull
  private final List<ICommand> commands = new LinkedList<>();
  @NonNull
  private final String exec;
  @NonNull
  private final Map<String, IVersionInfo> versionInfos;

  /**
   * The main entry point for command execution.
   *
   * @param args
   *          the command line arguments to process
   */
  public static void main(String... args) {
    System.setProperty("java.util.logging.manager", "org.apache.logging.log4j.jul.LogManager");
    CLIProcessor processor = new CLIProcessor("metaschema-cli");

    CommandService.getInstance().getCommands().stream().forEach(command -> {
      assert command != null;
      processor.addCommandHandler(command);
    });
    System.exit(processor.process(args).getExitCode().getStatusCode());
  }

  /**
   * The main entry point for CLI processing.
   * <p>
   * This uses the build-in version information.
   *
   * @param args
   *          the command line arguments
   */
  public CLIProcessor(@NonNull String args) {
    this(args, CollectionUtil.singletonMap(COMMAND_VERSION, new ProcessorVersion()));
  }

  /**
   * The main entry point for CLI processing.
   * <p>
   * This uses the provided version information.
   *
   * @param exec
   *          the command name
   * @param versionInfos
   *          the version info to display when the version option is provided
   */
  public CLIProcessor(@NonNull String exec, @NonNull Map<String, IVersionInfo> versionInfos) {
    this.exec = exec;
    this.versionInfos = versionInfos;
    AnsiConsole.systemInstall();
  }

  /**
   * Gets the command used to execute for use in help text.
   *
   * @return the command name
   */
  @NonNull
  public String getExec() {
    return exec;
  }

  /**
   * Retrieve the version information for this application.
   *
   * @return the versionInfo
   */
  @NonNull
  public Map<String, IVersionInfo> getVersionInfos() {
    return versionInfos;
  }

  /**
   * Register a new command handler.
   *
   * @param handler
   *          the command handler to register
   */
  public void addCommandHandler(@NonNull ICommand handler) {
    commands.add(handler);
  }

  /**
   * Process a set of CLIProcessor arguments.
   * <p>
   * process().getExitCode().getStatusCode()
   *
   * @param args
   *          the arguments to process
   * @return the exit status
   */
  @NonNull
  public ExitStatus process(String... args) {
    return parseCommand(args);
  }

  @NonNull
  private ExitStatus parseCommand(String... args) {
    List<String> commandArgs = Arrays.asList(args);
    assert commandArgs != null;
    CallingContext callingContext = new CallingContext(commandArgs);

    if (LOGGER.isDebugEnabled()) {
      String commandChain = callingContext.getCalledCommands().stream()
          .map(ICommand::getName)
          .collect(Collectors.joining(" -> "));
      LOGGER.debug("Processing command chain: {}", commandChain);
    }

    ExitStatus status;
    // the first two arguments should be the <command> and <operation>, where <type>
    // is the object type
    // the <operation> is performed against.
    if (commandArgs.isEmpty()) {
      status = ExitCode.INVALID_COMMAND.exit();
      callingContext.showHelp();
    } else {
      status = callingContext.processCommand();
    }
    return status;
  }

  /**
   * Get the root-level commands.
   *
   * @return the list of commands
   */
  @NonNull
  protected final List<ICommand> getTopLevelCommands() {
    return CollectionUtil.unmodifiableList(commands);
  }

  /**
   * Get the root-level commands, mapped from name to command.
   *
   * @return the map of command names to command
   */
  @NonNull
  protected final Map<String, ICommand> getTopLevelCommandsByName() {
    return ObjectUtils.notNull(getTopLevelCommands()
        .stream()
        .collect(Collectors.toUnmodifiableMap(ICommand::getName, Function.identity())));
  }

  private static void handleNoColor() {
    System.setProperty(AnsiConsole.JANSI_MODE, AnsiConsole.JANSI_MODE_STRIP);
    AnsiConsole.systemUninstall();
  }

  /**
   * Configure the logger to only report errors.
   */
  public static void handleQuiet() {
    LoggerContext ctx = (LoggerContext) LogManager.getContext(false); // NOPMD not closable here
    Configuration config = ctx.getConfiguration();
    LoggerConfig loggerConfig = config.getLoggerConfig(LogManager.ROOT_LOGGER_NAME);
    Level oldLevel = loggerConfig.getLevel();
    if (oldLevel.isLessSpecificThan(Level.ERROR)) {
      loggerConfig.setLevel(Level.ERROR);
      ctx.updateLoggers();
    }
  }

  /**
   * Output version information.
   */
  protected void showVersion() {
    @SuppressWarnings("resource")
    PrintStream out = AnsiConsole.out(); // NOPMD - not owner
    getVersionInfos().values().stream().forEach(info -> {
      out.println(ansi()
          .bold().a(info.getName()).boldOff()
          .a(" ")
          .bold().a(info.getVersion()).boldOff()
          .a(" built at ")
          .bold().a(info.getBuildTimestamp()).boldOff()
          .a(" from branch ")
          .bold().a(info.getGitBranch()).boldOff()
          .a(" (")
          .bold().a(info.getGitCommit()).boldOff()
          .a(") at ")
          .bold().a(info.getGitOriginUrl()).boldOff()
          .reset());
    });
    out.flush();
  }

  /**
   * Records information about the command line options and called command
   * hierarchy.
   */
  @SuppressWarnings("PMD.GodClass")
  public final class CallingContext {
    @NonNull
    private final List<Option> options;
    @NonNull
    private final List<ICommand> calledCommands;
    @Nullable
    private final ICommand targetCommand;
    @NonNull
    private final List<String> extraArgs;

    @SuppressFBWarnings(value = "CT_CONSTRUCTOR_THROW", justification = "Use of final fields")
    private CallingContext(@NonNull List<String> args) {
      @SuppressWarnings("PMD.LooseCoupling") // needed to support getLast
      LinkedList<ICommand> calledCommands = new LinkedList<>();
      List<Option> options = new LinkedList<>(OPTIONS);
      List<String> extraArgs = new LinkedList<>();

      AtomicBoolean endArgs = new AtomicBoolean();
      args.forEach(arg -> {
        if (endArgs.get() || arg.startsWith("-")) {
          extraArgs.add(arg);
        } else if ("--".equals(arg)) {
          endArgs.set(true);
        } else {
          ICommand command = calledCommands.isEmpty()
              ? getTopLevelCommandsByName().get(arg)
              : calledCommands.getLast().getSubCommandByName(arg);

          if (command == null) {
            extraArgs.add(arg);
            endArgs.set(true);
          } else {
            calledCommands.add(command);
            options.addAll(command.gatherOptions());
          }
        }
      });

      this.calledCommands = CollectionUtil.unmodifiableList(calledCommands);
      this.targetCommand = calledCommands.peekLast();
      this.options = CollectionUtil.unmodifiableList(options);
      this.extraArgs = CollectionUtil.unmodifiableList(extraArgs);
    }

    /**
     * Get the command line processor instance that generated this calling context.
     *
     * @return the instance
     */
    @NonNull
    public CLIProcessor getCLIProcessor() {
      return CLIProcessor.this;
    }

    /**
     * Get the command that was triggered by the CLI arguments.
     *
     * @return the command or {@code null} if no command was triggered
     */
    @Nullable
    public ICommand getTargetCommand() {
      return targetCommand;
    }

    /**
     * Get the options that are in scope for the current command context.
     *
     * @return the list of options
     */
    @NonNull
    private List<Option> getOptionsList() {
      return options;
    }

    @NonNull
    private List<ICommand> getCalledCommands() {
      return calledCommands;
    }

    /**
     * Get any left over arguments that were not consumed by CLI options.
     *
     * @return the list of remaining arguments, which may be empty
     */
    @NonNull
    private List<String> getExtraArgs() {
      return extraArgs;
    }

    /**
     * Get the collections of in scope options as an options group.
     *
     * @return the options group
     */
    private Options toOptions() {
      Options retval = new Options();
      for (Option option : getOptionsList()) {
        retval.addOption(option);
      }
      return retval;
    }

    /**
     * Process the command identified by the CLI arguments.
     *
     * @return the result of processing the command
     */
    @SuppressWarnings({
        "PMD.OnlyOneReturn",
        "PMD.CyclomaticComplexity"
    })
    @NonNull
    public ExitStatus processCommand() {
      // TODO: Consider refactoring as follows to reduce complexity:
      // - Extract the parsing logic for each phase into separate methods (e.g.,
      // parsePhaseOneOptions, parsePhaseTwoOptions).
      // - Encapsulate error handling into dedicated methods.
      // - Separate command execution logic into its own method if possible.
      CommandLineParser parser = new DefaultParser();

      // this uses a three phase approach where:
      // phase 1: checks if help or version are used
      // phase 2: parse and validate arguments
      // phase 3: executes the command

      // phase 1
      CommandLine cmdLine;
      try {
        Options phase1Options = new Options();
        phase1Options.addOption(HELP_OPTION);
        phase1Options.addOption(VERSION_OPTION);

        cmdLine = ObjectUtils.notNull(parser.parse(phase1Options, getExtraArgs().toArray(new String[0]), true));
      } catch (ParseException ex) {
        String msg = ex.getMessage();
        assert msg != null;
        return handleInvalidCommand(msg);
      }

      if (cmdLine.hasOption(VERSION_OPTION)) {
        showVersion();
        return ExitCode.OK.exit();
      }
      if (cmdLine.hasOption(HELP_OPTION)) {
        showHelp();
        return ExitCode.OK.exit();
      }

      // phase 2
      try {
        cmdLine = ObjectUtils.notNull(parser.parse(toOptions(), getExtraArgs().toArray(new String[0])));
      } catch (ParseException ex) {
        String msg = ex.getMessage();
        assert msg != null;
        return handleInvalidCommand(msg);
      }

      ICommand targetCommand = getTargetCommand();
      if (targetCommand != null) {
        try {
          targetCommand.validateExtraArguments(this, cmdLine);
        } catch (InvalidArgumentException ex) {
          return handleError(
              ExitCode.INVALID_ARGUMENTS.exitMessage(ex.getLocalizedMessage()),
              cmdLine,
              true);
        }
      }

      for (ICommand cmd : getCalledCommands()) {
        try {
          cmd.validateOptions(this, cmdLine);
        } catch (InvalidArgumentException ex) {
          String msg = ex.getMessage();
          assert msg != null;
          return handleInvalidCommand(msg);
        }
      }

      // phase 3
      if (cmdLine.hasOption(NO_COLOR_OPTION)) {
        handleNoColor();
      }

      if (cmdLine.hasOption(QUIET_OPTION)) {
        handleQuiet();
      }
      return invokeCommand(cmdLine);
    }

    /**
     * Directly execute the logic associated with the command.
     *
     * @param cmdLine
     *          the command line information
     * @return the result of executing the command
     */
    @SuppressWarnings({
        "PMD.AvoidCatchingGenericException" // needed here
    })
    @NonNull
    private ExitStatus invokeCommand(@NonNull CommandLine cmdLine) {
      ExitStatus retval;
      try {
        ICommand targetCommand = getTargetCommand();
        if (targetCommand == null) {
          retval = ExitCode.INVALID_COMMAND.exit();
        } else {
          ICommandExecutor executor = targetCommand.newExecutor(this, cmdLine);
          try {
            executor.execute();
            retval = ExitCode.OK.exit();
          } catch (CommandExecutionException ex) {
            retval = ex.toExitStatus();
          } catch (RuntimeException ex) {
            retval = ExitCode.RUNTIME_ERROR
                .exitMessage("Unexpected error occured: " + ex.getLocalizedMessage())
                .withThrowable(ex);
          }
        }
      } catch (RuntimeException ex) {
        retval = ExitCode.RUNTIME_ERROR
            .exitMessage(String.format("An uncaught runtime error occurred. %s", ex.getLocalizedMessage()))
            .withThrowable(ex);
      }

      if (!ExitCode.OK.equals(retval.getExitCode())) {
        retval.generateMessage(cmdLine.hasOption(SHOW_STACK_TRACE_OPTION));

        if (ExitCode.INVALID_COMMAND.equals(retval.getExitCode())) {
          showHelp();
        }
      }
      return retval;
    }

    /**
     * Handle an error that occurred while executing the command.
     *
     * @param exitStatus
     *          the execution result
     * @param cmdLine
     *          the command line information
     * @param showHelp
     *          if {@code true} show the help information
     * @return the resulting exit status
     */
    @NonNull
    public ExitStatus handleError(
        @NonNull ExitStatus exitStatus,
        @NonNull CommandLine cmdLine,
        boolean showHelp) {
      exitStatus.generateMessage(cmdLine.hasOption(SHOW_STACK_TRACE_OPTION));
      if (showHelp) {
        showHelp();
      }
      return exitStatus;
    }

    /**
     * Generate the help message and exit status for an invalid command using the
     * provided message.
     *
     * @param message
     *          the error message
     * @return the resulting exit status
     */
    @NonNull
    public ExitStatus handleInvalidCommand(
        @NonNull String message) {
      showHelp();

      ExitStatus retval = ExitCode.INVALID_COMMAND.exitMessage(message);
      retval.generateMessage(false);
      return retval;
    }

    /**
     * Callback for providing a help header.
     *
     * @return the header or {@code null}
     */
    @Nullable
    private String buildHelpHeader() {
      // TODO: build a suitable header
      return null;
    }

    /**
     * Callback for providing a help footer.
     *
     * @param exec
     *          the executable name
     *
     * @return the footer or {@code null}
     */
    @NonNull
    private String buildHelpFooter() {

      ICommand targetCommand = getTargetCommand();
      Collection<ICommand> subCommands;
      if (targetCommand == null) {
        subCommands = getTopLevelCommands();
      } else {
        subCommands = targetCommand.getSubCommands();
      }

      String retval;
      if (subCommands.isEmpty()) {
        retval = "";
      } else {
        StringBuilder builder = new StringBuilder(128);
        builder
            .append(System.lineSeparator())
            .append("The following are available commands:")
            .append(System.lineSeparator());

        int length = subCommands.stream()
            .mapToInt(command -> command.getName().length())
            .max().orElse(0);

        for (ICommand command : subCommands) {
          builder.append(
              ansi()
                  .render(String.format("   @|bold %-" + length + "s|@ %s%n",
                      command.getName(),
                      command.getDescription())));
        }
        builder
            .append(System.lineSeparator())
            .append('\'')
            .append(getExec())
            .append(" <command> --help' will show help on that specific command.")
            .append(System.lineSeparator());
        retval = builder.toString();
        assert retval != null;
      }
      return retval;
    }

    /**
     * Get the CLI syntax.
     *
     * @return the CLI syntax to display in help output
     */
    private String buildHelpCliSyntax() {

      StringBuilder builder = new StringBuilder(64);
      builder.append(getExec());

      List<ICommand> calledCommands = getCalledCommands();
      if (!calledCommands.isEmpty()) {
        builder.append(calledCommands.stream()
            .map(ICommand::getName)
            .collect(Collectors.joining(" ", " ", "")));
      }

      // output calling commands
      ICommand targetCommand = getTargetCommand();
      if (targetCommand == null) {
        builder.append(" <command>");
      } else {
        builder.append(getSubCommands(targetCommand));
      }

      // output required options
      getOptionsList().stream()
          .filter(Option::isRequired)
          .forEach(option -> {
            builder
                .append(' ')
                .append(OptionUtils.toArgument(ObjectUtils.notNull(option)));
            if (option.hasArg()) {
              builder
                  .append('=')
                  .append(option.getArgName());
            }
          });

      // output non-required option placeholder
      builder.append(" [<options>]");

      // output extra arguments
      if (targetCommand != null) {
        // handle extra arguments
        builder.append(getExtraArguments(targetCommand));
      }

      String retval = builder.toString();
      assert retval != null;
      return retval;
    }

    @NonNull
    private CharSequence getSubCommands(ICommand targetCommand) {
      Collection<ICommand> subCommands = targetCommand.getSubCommands();

      StringBuilder builder = new StringBuilder();
      if (!subCommands.isEmpty()) {
        builder.append(' ');
        if (!targetCommand.isSubCommandRequired()) {
          builder.append('[');
        }

        builder.append("<command>");

        if (!targetCommand.isSubCommandRequired()) {
          builder.append(']');
        }
      }
      return builder;
    }

    @NonNull
    private CharSequence getExtraArguments(@NonNull ICommand targetCommand) {
      StringBuilder builder = new StringBuilder();
      for (ExtraArgument argument : targetCommand.getExtraArguments()) {
        builder.append(' ');
        if (!argument.isRequired()) {
          builder.append('[');
        }

        builder.append('<')
            .append(argument.getName())
            .append('>');

        if (argument.getNumber() > 1) {
          builder.append("...");
        }

        if (!argument.isRequired()) {
          builder.append(']');
        }
      }
      return builder;
    }

    /**
     * Output the help text to the console.
     */
    public void showHelp() {

      HelpFormatter formatter = new HelpFormatter();
      formatter.setLongOptSeparator("=");

      @SuppressWarnings("resource")
      AnsiPrintStream out = AnsiConsole.out();

      try (PrintWriter writer = new PrintWriter(
          AutoCloser.preventClose(out),
          true,
          StandardCharsets.UTF_8)) {
        formatter.printHelp(
            writer,
            Math.max(out.getTerminalWidth(), 50),
            buildHelpCliSyntax(),
            buildHelpHeader(),
            toOptions(),
            HelpFormatter.DEFAULT_LEFT_PAD,
            HelpFormatter.DEFAULT_DESC_PAD,
            buildHelpFooter(),
            false);
        writer.flush();
      }
    }
  }
}
