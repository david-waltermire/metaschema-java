/*
 * Portions of this software was developed by employees of the National Institute
 * of Standards and Technology (NIST), an agency of the Federal Government and is
 * being made available as a public service. Pursuant to title 17 United States
 * Code Section 105, works of NIST employees are not subject to copyright
 * protection in the United States. This software may be subject to foreign
 * copyright. Permission in the United States and in foreign countries, to the
 * extent that NIST may hold copyright, to use, copy, modify, create derivative
 * works, and distribute this software and its documentation without fee is hereby
 * granted on a non-exclusive basis, provided that this notice and disclaimer
 * of warranty appears in all copies.
 *
 * THE SOFTWARE IS PROVIDED 'AS IS' WITHOUT ANY WARRANTY OF ANY KIND, EITHER
 * EXPRESSED, IMPLIED, OR STATUTORY, INCLUDING, BUT NOT LIMITED TO, ANY WARRANTY
 * THAT THE SOFTWARE WILL CONFORM TO SPECIFICATIONS, ANY IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND FREEDOM FROM
 * INFRINGEMENT, AND ANY WARRANTY THAT THE DOCUMENTATION WILL CONFORM TO THE
 * SOFTWARE, OR ANY WARRANTY THAT THE SOFTWARE WILL BE ERROR FREE.  IN NO EVENT
 * SHALL NIST BE LIABLE FOR ANY DAMAGES, INCLUDING, BUT NOT LIMITED TO, DIRECT,
 * INDIRECT, SPECIAL OR CONSEQUENTIAL DAMAGES, ARISING OUT OF, RESULTING FROM,
 * OR IN ANY WAY CONNECTED WITH THIS SOFTWARE, WHETHER OR NOT BASED UPON WARRANTY,
 * CONTRACT, TORT, OR OTHERWISE, WHETHER OR NOT INJURY WAS SUSTAINED BY PERSONS OR
 * PROPERTY OR OTHERWISE, AND WHETHER OR NOT LOSS WAS SUSTAINED FROM, OR AROSE OUT
 * OF THE RESULTS OF, OR USE OF, THE SOFTWARE OR SERVICES PROVIDED HEREUNDER.
 */

package gov.nist.secauto.metaschema.modules.sarif;

import gov.nist.csrc.ns.oscal.metaschema.validation.results.x10.Location;
import gov.nist.csrc.ns.oscal.metaschema.validation.results.x10.Message;
import gov.nist.csrc.ns.oscal.metaschema.validation.results.x10.PhysicalLocation;
import gov.nist.csrc.ns.oscal.metaschema.validation.results.x10.Region;
import gov.nist.csrc.ns.oscal.metaschema.validation.results.x10.Result;
import gov.nist.csrc.ns.oscal.metaschema.validation.results.x10.Run;
import gov.nist.csrc.ns.oscal.metaschema.validation.results.x10.Sarif;
import gov.nist.secauto.metaschema.core.model.IResourceLocation;
import gov.nist.secauto.metaschema.core.model.constraint.ConstraintValidationFinding;
import gov.nist.secauto.metaschema.core.model.constraint.IConstraint;
import gov.nist.secauto.metaschema.core.model.constraint.IConstraint.Level;
import gov.nist.secauto.metaschema.core.model.validation.IValidationFinding;
import gov.nist.secauto.metaschema.core.model.validation.IValidationResult;
import gov.nist.secauto.metaschema.core.model.validation.JsonSchemaContentValidator.JsonValidationFinding;
import gov.nist.secauto.metaschema.core.model.validation.XmlSchemaContentValidator.XmlValidationFinding;
import gov.nist.secauto.metaschema.databind.IBindingContext;
import gov.nist.secauto.metaschema.databind.io.Format;
import gov.nist.secauto.metaschema.databind.io.SerializationFeature;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.LinkedList;
import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

public final class SarifValidationHandler {
  private enum Kind {
    NOT_APPLICABLE("notApplicable"),
    PASS("pass"),
    FAIL("fail"),
    REVIEW("review"),
    OPEN("open"),
    INFORMATIONAL("informational");

    @NonNull
    private final String label;

    Kind(@NonNull String label) {
      this.label = label;
    }

    @NonNull
    public String getLabel() {
      return label;
    }
  }

  private enum SeverityLevel {
    NONE("none"),
    NOTE("note"),
    WARNING("warning"),
    ERROR("error");

    @NonNull
    private final String label;

    SeverityLevel(@NonNull String label) {
      this.label = label;
    }

    @NonNull
    public String getLabel() {
      return label;
    }
  }

  private static final SarifValidationHandler INSTANCE = new SarifValidationHandler();

  @SuppressFBWarnings(value = "SING_SINGLETON_GETTER_NOT_SYNCHRONIZED",
      justification = "both values are class initialized")
  public static SarifValidationHandler instance() {
    return INSTANCE;
  }

  private SarifValidationHandler() {
    // disable construction
  }

  public boolean handleValidationResults(
      @NonNull URI source,
      @NonNull Path outputFile,
      @NonNull IValidationResult validationResult,
      @NonNull IBindingContext bindingContext) throws IOException {

    Sarif sarif = new Sarif();
    sarif.setVersion("2.1.0");

    Run run = new Run();
    sarif.addRun(run);

    handleValidationFindings(validationResult.getFindings(), run);

    bindingContext.newSerializer(Format.JSON, Sarif.class)
        .disableFeature(SerializationFeature.SERIALIZE_ROOT)
        .serialize(
            sarif,
            outputFile,
            StandardOpenOption.CREATE,
            StandardOpenOption.WRITE,
            StandardOpenOption.TRUNCATE_EXISTING);

    return validationResult.isPassing();
  }

  public void handleValidationFindings(
      @NonNull List<? extends IValidationFinding> findings,
      @NonNull Run run) {

    for (IValidationFinding finding : findings) {
      if (finding instanceof JsonValidationFinding) {
        run.addResult(handleJsonValidationFinding((JsonValidationFinding) finding));
      } else if (finding instanceof XmlValidationFinding) {
        run.addResult(handleXmlValidationFinding((XmlValidationFinding) finding));
      } else if (finding instanceof ConstraintValidationFinding) {
        handleConstraintValidationFinding((ConstraintValidationFinding) finding).stream()
            .forEachOrdered(run::addResult);
      } else {
        throw new IllegalStateException();
      }
    }
  }

  private Result handleJsonValidationFinding(@NonNull JsonValidationFinding finding) {
    Result result = new Result();

    result.setKind(kind(finding).getLabel());
    result.setLevel(level(finding.getSeverity()).getLabel());
    message(finding, result);
    location(finding, result);
    // retval.setMessage(message(finding.getMessage()));
    //
    //
    // getLogger(finding).log(
    // ansi.a('[')
    // .a(finding.getCause().getPointerToViolation())
    // .reset()
    // .a(']')
    // .format(" %s [%s]",
    // finding.getMessage(),
    // finding.getDocumentUri().toString()));

    return result;
  }

  @NonNull
  private Kind kind(@NonNull IValidationFinding finding) {
    IValidationFinding.Kind kind = finding.getKind();

    Kind retval;
    switch (kind) {
    case FAIL:
      retval = Kind.FAIL;
      break;
    case INFORMATIONAL:
      retval = Kind.INFORMATIONAL;
      break;
    case NOT_APPLICABLE:
      retval = Kind.NOT_APPLICABLE;
      break;
    case PASS:
      retval = Kind.PASS;
      break;
    default:
      throw new IllegalArgumentException(String.format("Invalid finding kind '%s'.", kind));
    }
    return retval;
  }

  @NonNull
  private SeverityLevel level(@NonNull Level severity) {
    SeverityLevel retval;
    switch (severity) {
    case CRITICAL:
    case ERROR:
      retval = SeverityLevel.ERROR;
      break;
    case INFORMATIONAL:
    case DEBUG:
      retval = SeverityLevel.NOTE;
      break;
    case WARNING:
      retval = SeverityLevel.WARNING;
      break;
    case NONE:
      retval = SeverityLevel.NONE;
      break;
    default:
      throw new IllegalArgumentException(String.format("Invalid severity '%s'.", severity));
    }
    return retval;
  }

  private void message(@NonNull IValidationFinding finding, @NonNull Result result) {
    String message = finding.getMessage();
    if (message != null) {
      Message msg = new Message();
      msg.setText(message);
      result.setMessage(msg);
    }
  }

  private void location(@NonNull IValidationFinding finding, @NonNull Result result) {
    IResourceLocation location = finding.getLocation();
    if (location != null) {
      Region region = new Region();

      if (location.getLine() > -1) {
        region.setStartLine(BigInteger.valueOf(location.getLine()));
      }
      if (location.getColumn() > -1) {
        region.setStartColumn(BigInteger.valueOf(location.getColumn()));
      }
      if (location.getByteOffset() > -1) {
        region.setByteOffset(BigInteger.valueOf(location.getByteOffset()));
      }
      if (location.getCharOffset() > -1) {
        region.setCharOffset(BigInteger.valueOf(location.getCharOffset()));
      }

      PhysicalLocation physical = new PhysicalLocation();
      physical.setRegion(region);

      Location loc = new Location();
      loc.setPhysicalLocation(physical);
      result.setLocation(loc);
    }
  }

  private Result handleXmlValidationFinding(@NonNull XmlValidationFinding finding) {
    Result result = new Result();

    result.setKind(kind(finding).getLabel());
    result.setLevel(level(finding.getSeverity()).getLabel());
    message(finding, result);
    location(finding, result);

    // SAXParseException ex = finding.getCause();
    //
    // getLogger(finding).log(
    // ansi.format("%s [%s{%d,%d}]",
    // finding.getMessage(),
    // finding.getDocumentUri().toString(),
    // ex.getLineNumber(),
    // ex.getColumnNumber()));

    return result;
  }

  private List<Result> handleConstraintValidationFinding(@NonNull ConstraintValidationFinding finding) {
    List<Result> retval = new LinkedList<>();

    Kind kind = kind(finding);
    SeverityLevel level = level(finding.getSeverity());

    for (IConstraint constraint : finding.getConstraints()) {

      Result result = new Result();

      String id = constraint.getId();
      if (id != null) {
        result.setRuleId(id);
      }
      result.setKind(kind.getLabel());
      result.setLevel(level.getLabel());
      message(finding, result);
      location(finding, result);

      // getLogger(finding).log(
      // ansi.format("[%s] %s", finding.getNode().getMetapath(),
      // finding.getMessage()));

      retval.add(result);
    }
    return retval;
  }
  //
  // @NonNull
  // private LogBuilder getLogger(@NonNull IValidationFinding finding) {
  // LogBuilder retval;
  // switch (finding.getSeverity()) {
  // case CRITICAL:
  // retval = LOGGER.atFatal();
  // break;
  // case ERROR:
  // retval = LOGGER.atError();
  // break;
  // case WARNING:
  // retval = LOGGER.atWarn();
  // break;
  // case INFORMATIONAL:
  // retval = LOGGER.atInfo();
  // break;
  // default:
  // throw new IllegalArgumentException("Unknown level: " +
  // finding.getSeverity().name());
  // }
  //
  // assert retval != null;
  //
  // if (finding.getCause() != null && isLogExceptions()) {
  // retval.withThrowable(finding.getCause());
  // }
  //
  // return retval;
  // }
  //
  // @SuppressWarnings("static-method")
  // @NonNull
  // private Ansi generatePreamble(@NonNull Level level) {
  //
  // switch (level) {
  // case CRITICAL:
  // ansi = ansi.fgRed().a("CRITICAL").reset();
  // break;
  // case ERROR:
  // ansi = ansi.fgBrightRed().a("ERROR").reset();
  // break;
  // case WARNING:
  // ansi = ansi.fgBrightYellow().a("WARNING").reset();
  // break;
  // case INFORMATIONAL:
  // ansi = ansi.fgBrightBlue().a("INFO").reset();
  // break;
  // default:
  // ansi = ansi().a(level.name()).reset();
  // break;
  // }
  // ansi = ansi.a("] ").reset();
  //
  // assert ansi != null;
  // return ansi;
  // }
}
