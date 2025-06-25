/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.cli.util;

import static org.fusesource.jansi.Ansi.ansi;

import gov.nist.secauto.metaschema.core.model.constraint.ConstraintValidationFinding;
import gov.nist.secauto.metaschema.core.model.constraint.IConstraint.Level;
import gov.nist.secauto.metaschema.core.model.validation.AbstractValidationResultProcessor;
import gov.nist.secauto.metaschema.core.model.validation.IValidationFinding;
import gov.nist.secauto.metaschema.core.model.validation.JsonSchemaContentValidator.JsonValidationFinding;
import gov.nist.secauto.metaschema.core.model.validation.XmlSchemaContentValidator.XmlValidationFinding;
import gov.nist.secauto.metaschema.modules.sarif.SarifValidationHandler;

import org.apache.logging.log4j.LogBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.fusesource.jansi.Ansi;
import org.fusesource.jansi.Ansi.Color;
import org.xml.sax.SAXParseException;

import java.net.URI;
import java.util.Set;
import java.util.stream.Collectors;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

/**
 * Supports logging validation findings to the console using ANSI color codes to
 * improve the visibility of warnings and errors.
 */
public final class LoggingValidationHandler
    extends AbstractValidationResultProcessor {
  private static final Logger LOGGER = LogManager.getLogger(LoggingValidationHandler.class);

  @NonNull
  private static final LoggingValidationHandler NO_LOG_EXCPTION_INSTANCE = new LoggingValidationHandler(false);
  @NonNull
  private static final LoggingValidationHandler LOG_EXCPTION_INSTANCE = new LoggingValidationHandler(true);

  private final boolean logExceptions;

  /**
   * Get a singleton instance of the logging validation handler.
   * <p>
   * This instance will not log exceptions.
   *
   * @return the instance
   */
  @NonNull
  public static LoggingValidationHandler instance() {
    return instance(false);
  }

  /**
   * Get a singleton instance of the logging validation handler.
   *
   * @param logExceptions
   *          {@code true} if this instance will log exceptions or {@code false}
   *          otherwise
   * @return the instance
   */
  @SuppressFBWarnings(value = "SING_SINGLETON_GETTER_NOT_SYNCHRONIZED",
      justification = "both values are class initialized")
  @NonNull
  public static LoggingValidationHandler instance(boolean logExceptions) {
    return logExceptions ? LOG_EXCPTION_INSTANCE : NO_LOG_EXCPTION_INSTANCE;
  }

  private LoggingValidationHandler(boolean logExceptions) {
    this.logExceptions = logExceptions;
  }

  /**
   * Determine if exceptions should be logged.
   *
   * @return {@code true} if exceptions are logged or {@code false} otherwise
   */
  public boolean isLogExceptions() {
    return logExceptions;
  }

  @Override
  protected void handleJsonValidationFinding(@NonNull JsonValidationFinding finding) {
    Ansi ansi = generatePreamble(finding.getSeverity());

    ansi = ansi.a('[')
        .fgBright(Color.WHITE)
        .a(finding.getCause().getPointerToViolation())
        .reset()
        .a(']');

    URI documentUri = finding.getDocumentUri();
    ansi = documentUri == null
        ? ansi.format(" %s", finding.getMessage())
        : ansi.format(" %s [%s]", finding.getMessage(), documentUri.toString());

    getLogger(finding).log(ansi);
  }

  @Override
  protected void handleXmlValidationFinding(XmlValidationFinding finding) {
    Ansi ansi = generatePreamble(finding.getSeverity());
    SAXParseException ex = finding.getCause();

    URI documentUri = finding.getDocumentUri();
    ansi = documentUri == null
        ? ansi.format("%s [{%d,%d}]",
            finding.getMessage(),
            ex.getLineNumber(),
            ex.getColumnNumber())
        : ansi.format("%s [%s{%d,%d}]",
            finding.getMessage(),
            documentUri.toString(),
            ex.getLineNumber(),
            ex.getColumnNumber());

    getLogger(finding).log(ansi);
  }

  @Override
  protected void handleConstraintValidationFinding(@NonNull ConstraintValidationFinding finding) {
    Ansi ansi = generatePreamble(finding.getSeverity());

    ansi.format("[%s]", finding.getTarget().getMetapath());

    String id = finding.getIdentifier();
    if (id != null) {
      ansi.format(" %s:", id);
    }

    ansi.format(" %s", finding.getMessage());

    Set<String> helpUrls = finding.getConstraints().stream()
        .flatMap(constraint -> constraint.getPropertyValues(SarifValidationHandler.SARIF_HELP_URL_KEY).stream())
        .collect(Collectors.toSet());
    if (!helpUrls.isEmpty()) {
      ansi.format(" (help: %s)",
          helpUrls.stream().collect(Collectors.joining(", ")));
    }

    getLogger(finding).log(ansi);
  }

  @NonNull
  @SuppressWarnings("PMD.CyclomaticComplexity")
  private LogBuilder getLogger(@NonNull IValidationFinding finding) {
    LogBuilder retval;
    switch (finding.getSeverity()) {
    case CRITICAL:
      retval = LOGGER.atFatal();
      break;
    case ERROR:
      retval = LOGGER.atError();
      break;
    case WARNING:
      retval = LOGGER.atWarn();
      break;
    case INFORMATIONAL:
      retval = LOGGER.atInfo();
      break;
    case DEBUG:
      retval = LOGGER.isDebugEnabled() ? LOGGER.atDebug() : LOGGER.atInfo();
      break;
    default:
      throw new IllegalArgumentException("Unknown level: " + finding.getSeverity().name());
    }

    assert retval != null;

    if (finding.getCause() != null && isLogExceptions()) {
      retval.withThrowable(finding.getCause());
    }

    return retval;
  }

  @SuppressWarnings("static-method")
  @NonNull
  private Ansi generatePreamble(@NonNull Level level) {
    Ansi ansi = ansi().fgBright(Color.WHITE).a('[').reset();

    switch (level) {
    case CRITICAL:
      ansi = ansi.fgRed().a("CRITICAL").reset();
      break;
    case ERROR:
      ansi = ansi.fgBrightRed().a("ERROR").reset();
      break;
    case WARNING:
      ansi = ansi.fgBrightYellow().a("WARNING").reset();
      break;
    case INFORMATIONAL:
      ansi = ansi.fgBrightBlue().a("INFO").reset();
      break;
    case DEBUG:
      ansi = ansi.fgBrightCyan().a("DEBUG").reset();
      break;
    default:
      ansi = ansi().fgBright(Color.MAGENTA).a(level.name()).reset();
      break;
    }
    ansi = ansi.fgBright(Color.WHITE).a("] ").reset();

    assert ansi != null;
    return ansi;
  }
}
