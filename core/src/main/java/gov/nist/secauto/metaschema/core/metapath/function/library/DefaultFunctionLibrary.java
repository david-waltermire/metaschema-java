/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.function.library;

import com.google.auto.service.AutoService;

import gov.nist.secauto.metaschema.core.metapath.MetapathConstants;
import gov.nist.secauto.metaschema.core.metapath.function.FunctionLibrary;
import gov.nist.secauto.metaschema.core.metapath.function.IFunctionLibrary;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IBooleanItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IDateItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IDateTimeItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IDecimalItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IDurationItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IIntegerItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.INcNameItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.INonNegativeIntegerItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.INumericItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IPositiveIntegerItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IStringItem;

@SuppressWarnings( "removal")
@AutoService(IFunctionLibrary.class)
public class DefaultFunctionLibrary
    extends FunctionLibrary {

  /**
   * Initialize the built-in function library.
   */
  @SuppressWarnings("deprecation")
  public DefaultFunctionLibrary() { // NOPMD - intentional
    // https://www.w3.org/TR/xpath-functions-31/#func-abs
    registerFunction(FnAbs.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-adjust-dateTime-to-timezone
    // https://www.w3.org/TR/xpath-functions-31/#func-adjust-date-to-timezone
    // https://www.w3.org/TR/xpath-functions-31/#func-adjust-time-to-timezone
    // https://www.w3.org/TR/xpath-functions-31/#func-avg
    registerFunction(FnAvg.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-base-uri
    registerFunction(FnBaseUri.SIGNATURE_NO_ARG);
    registerFunction(FnBaseUri.SIGNATURE_ONE_ARG);
    // https://www.w3.org/TR/xpath-functions-31/#func-boolean
    registerFunction(FnBoolean.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-ceiling
    registerFunction(FnCeiling.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-compare
    registerFunction(FnCompare.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-concat
    registerFunction(FnConcat.SIGNATURE);
    // P1: https://www.w3.org/TR/xpath-functions-31/#func-contains
    // https://www.w3.org/TR/xpath-functions-31/#func-count
    registerFunction(FnCount.SIGNATURE);
    // P2: https://www.w3.org/TR/xpath-functions-31/#func-current-date
    // https://www.w3.org/TR/xpath-functions-31/#func-current-dateTime
    registerFunction(FnCurrentDateTime.SIGNATURE);
    // P2: https://www.w3.org/TR/xpath-functions-31/#func-current-time
    // https://www.w3.org/TR/xpath-functions-31/#func-data
    registerFunction(FnData.SIGNATURE_NO_ARG);
    registerFunction(FnData.SIGNATURE_ONE_ARG);
    // https://www.w3.org/TR/xpath-functions-31/#func-day-from-date
    // https://www.w3.org/TR/xpath-functions-31/#func-day-from-dateTime
    // https://www.w3.org/TR/xpath-functions-31/#func-days-from-duration
    // P1: https://www.w3.org/TR/xpath-functions-31/#func-deep-equal
    // P1: https://www.w3.org/TR/xpath-functions-31/#func-distinct-values
    // https://www.w3.org/TR/xpath-functions-31/#func-doc
    registerFunction(FnDoc.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-doc-available
    registerFunction(FnDocumentAvailable.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-document-uri
    registerFunction(FnDocumentUri.SIGNATURE_NO_ARG);
    registerFunction(FnDocumentUri.SIGNATURE_ONE_ARG);
    // https://www.w3.org/TR/xpath-functions-31/#func-empty
    registerFunction(FnEmpty.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-encode-for-uri
    // P1: https://www.w3.org/TR/xpath-functions-31/#func-ends-with
    // P2: https://www.w3.org/TR/xpath-functions-31/#func-exactly-one
    // https://www.w3.org/TR/xpath-functions-31/#func-exists
    registerFunction(FnExists.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-false
    registerFunction(FnFalse.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-floor
    registerFunction(NumericFunction.signature(MetapathConstants.NS_METAPATH_FUNCTIONS, "floor", INumericItem::floor));
    // P2: https://www.w3.org/TR/xpath-functions-31/#func-format-date
    // P2: https://www.w3.org/TR/xpath-functions-31/#func-format-dateTime
    // P2: https://www.w3.org/TR/xpath-functions-31/#func-format-integer
    // P2: https://www.w3.org/TR/xpath-functions-31/#func-format-number
    // P2: https://www.w3.org/TR/xpath-functions-31/#func-format-time
    // P1: https://www.w3.org/TR/xpath-functions-31/#func-generate-id
    // P2: https://www.w3.org/TR/xpath-functions-31/#func-has-children
    // https://www.w3.org/TR/xpath-functions-31/#func-head
    registerFunction(FnHead.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-hours-from-dateTime
    // https://www.w3.org/TR/xpath-functions-31/#func-hours-from-duration
    // https://www.w3.org/TR/xpath-functions-31/#func-hours-from-time
    // https://www.w3.org/TR/xpath-functions-31/#func-implicit-timezone
    // P1: https://www.w3.org/TR/xpath-functions-31/#func-index-of
    // https://www.w3.org/TR/xpath-functions-31/#func-innermost
    // https://www.w3.org/TR/xpath-functions-31/#func-insert-before
    registerFunction(FnInsertBefore.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-iri-to-uri
    // P1: https://www.w3.org/TR/xpath-functions-31/#func-last
    // P1: https://www.w3.org/TR/xpath-functions-31/#func-lower-case
    // https://www.w3.org/TR/xpath-functions-31/#func-matches
    registerFunction(FnMatches.SIGNATURE_TWO_ARG);
    registerFunction(FnMatches.SIGNATURE_THREE_ARG);
    // https://www.w3.org/TR/xpath-functions-31/#func-max
    registerFunction(FnMinMax.SIGNATURE_MAX);
    // https://www.w3.org/TR/xpath-functions-31/#func-min
    registerFunction(FnMinMax.SIGNATURE_MIN);
    // https://www.w3.org/TR/xpath-functions-31/#func-minutes-from-dateTime
    // https://www.w3.org/TR/xpath-functions-31/#func-minutes-from-duration
    // https://www.w3.org/TR/xpath-functions-31/#func-minutes-from-time
    // https://www.w3.org/TR/xpath-functions-31/#func-month-from-date
    // https://www.w3.org/TR/xpath-functions-31/#func-month-from-dateTime
    // https://www.w3.org/TR/xpath-functions-31/#func-months-from-duration
    // https://www.w3.org/TR/xpath-functions-31/#func-node-name
    // https://www.w3.org/TR/xpath-functions-31/#func-normalize-space
    registerFunction(FnNormalizeSpace.SIGNATURE_NO_ARG);
    registerFunction(FnNormalizeSpace.SIGNATURE_ONE_ARG);
    // https://www.w3.org/TR/xpath-functions-31/#func-normalize-unicode
    // https://www.w3.org/TR/xpath-functions-31/#func-not
    registerFunction(FnNot.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-number
    // P2: https://www.w3.org/TR/xpath-functions-31/#func-one-or-more
    // https://www.w3.org/TR/xpath-functions-31/#func-outermost
    // https://www.w3.org/TR/xpath-functions-31/#func-parse-ietf-date
    // https://www.w3.org/TR/xpath-functions-31/#func-path
    registerFunction(FnPath.SIGNATURE_NO_ARG);
    registerFunction(FnPath.SIGNATURE_ONE_ARG);
    // P2: https://www.w3.org/TR/xpath-functions-31/#func-position
    // https://www.w3.org/TR/xpath-functions-31/#func-remove
    registerFunction(FnRemove.SIGNATURE);
    // P1: https://www.w3.org/TR/xpath-functions-31/#func-replace
    // https://www.w3.org/TR/xpath-functions-31/#func-resolve-uri
    registerFunction(FnResolveUri.SIGNATURE_ONE_ARG);
    registerFunction(FnResolveUri.SIGNATURE_TWO_ARG);
    // https://www.w3.org/TR/xpath-functions-31/#func-reverse
    registerFunction(FnReverse.SIGNATURE_ONE_ARG);
    // P1: https://www.w3.org/TR/xpath-functions-31/#func-root
    // https://www.w3.org/TR/xpath-functions-31/#func-round
    registerFunction(FnRound.SIGNATURE);
    registerFunction(FnRound.SIGNATURE_WITH_PRECISION);
    // P1: https://www.w3.org/TR/xpath-functions-31/#func-round-half-to-even
    // https://www.w3.org/TR/xpath-functions-31/#func-seconds-from-dateTime
    // https://www.w3.org/TR/xpath-functions-31/#func-seconds-from-duration
    // https://www.w3.org/TR/xpath-functions-31/#func-seconds-from-time
    // https://www.w3.org/TR/xpath-functions-31/#func-starts-with
    registerFunction(FnStartsWith.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-static-base-uri
    registerFunction(FnStaticBaseUri.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-string
    registerFunction(FnString.SIGNATURE_NO_ARG);
    registerFunction(FnString.SIGNATURE_ONE_ARG);
    // P1: https://www.w3.org/TR/xpath-functions-31/#func-string-join
    // P1: https://www.w3.org/TR/xpath-functions-31/#func-string-length
    // P1: https://www.w3.org/TR/xpath-functions-31/#func-subsequence
    // P1: https://www.w3.org/TR/xpath-functions-31/#func-substring
    // P1: https://www.w3.org/TR/xpath-functions-31/#func-substring-after
    // P1: https://www.w3.org/TR/xpath-functions-31/#func-substring-before
    // https://www.w3.org/TR/xpath-functions-31/#func-sum
    registerFunction(FnSum.SIGNATURE_ONE_ARG);
    registerFunction(FnSum.SIGNATURE_TWO_ARG);
    // https://www.w3.org/TR/xpath-functions-31/#func-tail
    registerFunction(FnTail.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-timezone-from-date
    // https://www.w3.org/TR/xpath-functions-31/#func-timezone-from-dateTime
    // https://www.w3.org/TR/xpath-functions-31/#func-timezone-from-time
    // https://www.w3.org/TR/xpath-functions-31/#func-tokenize
    registerFunction(FnTokenize.SIGNATURE_ONE_ARG);
    registerFunction(FnTokenize.SIGNATURE_TWO_ARG);
    registerFunction(FnTokenize.SIGNATURE_THREE_ARG);
    // P1: https://www.w3.org/TR/xpath-functions-31/#func-translate
    // https://www.w3.org/TR/xpath-functions-31/#func-true
    registerFunction(FnTrue.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-unparsed-text
    // https://www.w3.org/TR/xpath-functions-31/#func-unparsed-text-available
    // https://www.w3.org/TR/xpath-functions-31/#func-unparsed-text-lines
    // P1: https://www.w3.org/TR/xpath-functions-31/#func-upper-case
    // https://www.w3.org/TR/xpath-functions-31/#func-year-from-date
    // https://www.w3.org/TR/xpath-functions-31/#func-year-from-dateTime
    // https://www.w3.org/TR/xpath-functions-31/#func-years-from-duration
    // P2: https://www.w3.org/TR/xpath-functions-31/#func-zero-or-one

    // https://www.w3.org/TR/xpath-functions-31/#func-array-get
    registerFunction(ArrayGet.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-array-size
    registerFunction(ArraySize.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-array-put
    registerFunction(ArrayPut.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-array-append
    registerFunction(ArrayAppend.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-array-subarray
    registerFunction(ArraySubarray.SIGNATURE_TWO_ARG);
    registerFunction(ArraySubarray.SIGNATURE_THREE_ARG);
    // https://www.w3.org/TR/xpath-functions-31/#func-array-remove
    registerFunction(ArrayRemove.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-array-insert-before
    registerFunction(ArrayInsertBefore.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-array-head
    registerFunction(ArrayHead.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-array-tail
    registerFunction(ArrayTail.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-array-reverse
    registerFunction(ArrayReverse.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-array-join
    registerFunction(ArrayJoin.SIGNATURE);
    // P3: https://www.w3.org/TR/xpath-functions-31/#func-array-for-each
    // P3: https://www.w3.org/TR/xpath-functions-31/#func-array-filter
    // P3: https://www.w3.org/TR/xpath-functions-31/#func-array-fold-left
    // P3: https://www.w3.org/TR/xpath-functions-31/#func-array-fold-right
    // P3: https://www.w3.org/TR/xpath-functions-31/#func-array-for-each-pair
    // P3: https://www.w3.org/TR/xpath-functions-31/#func-array-sort
    // https://www.w3.org/TR/xpath-functions-31/#func-array-flatten
    registerFunction(ArrayFlatten.SIGNATURE);

    // https://www.w3.org/TR/xpath-functions-31/#func-map-merge
    registerFunction(MapMerge.SIGNATURE_ONE_ARG);
    registerFunction(MapMerge.SIGNATURE_TWO_ARG);
    // https://www.w3.org/TR/xpath-functions-31/#func-map-size
    registerFunction(MapSize.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-map-keys
    registerFunction(MapKeys.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-map-contains
    registerFunction(MapContains.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-map-get
    registerFunction(MapGet.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-map-find
    registerFunction(MapFind.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-map-put
    registerFunction(MapPut.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-map-entry
    registerFunction(MapEntry.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-map-remove
    registerFunction(MapRemove.SIGNATURE);
    // P3: https://www.w3.org/TR/xpath-functions-31/#func-map-for-each

    // // xpath casting functions
    // registerFunction(
    // CastFunction.signature(MetapathConstants.NS_XML_SCHEMA, "boolean",
    // IBooleanItem.class, IBooleanItem::cast));
    // registerFunction(CastFunction.signature(
    // MetapathConstants.NS_XML_SCHEMA, "date", IDateItem.class, IDateItem::cast));
    // registerFunction(CastFunction.signature(
    // MetapathConstants.NS_XML_SCHEMA, "dateTime", IDateTimeItem.class,
    // IDateTimeItem::cast));
    // registerFunction(CastFunction.signature(
    // MetapathConstants.NS_XML_SCHEMA, "decimal", IDecimalItem.class,
    // IDecimalItem::cast));
    // registerFunction(CastFunction.signature(
    // MetapathConstants.NS_XML_SCHEMA, "duration", IDurationItem.class,
    // IDurationItem::cast));
    // registerFunction(CastFunction.signature(
    // MetapathConstants.NS_XML_SCHEMA, "integer", IIntegerItem.class,
    // IIntegerItem::cast));
    // registerFunction(CastFunction.signature(
    // MetapathConstants.NS_XML_SCHEMA, "NCName", INcNameItem.class,
    // INcNameItem::cast));
    // registerFunction(CastFunction.signature(
    // MetapathConstants.NS_XML_SCHEMA, "nonNegativeInteger",
    // INonNegativeIntegerItem.class,
    // INonNegativeIntegerItem::cast));
    // registerFunction(CastFunction.signature(
    // MetapathConstants.NS_XML_SCHEMA, "positiveInteger",
    // IPositiveIntegerItem.class,
    // IPositiveIntegerItem::cast));
    // registerFunction(CastFunction.signature(
    // MetapathConstants.NS_XML_SCHEMA, "string", IStringItem.class,
    // IStringItem::cast));

    // metapath casting functions
    registerFunction(CastFunction.signature(
        MetapathConstants.NS_METAPATH, "boolean", IBooleanItem.class, IBooleanItem::cast));
    registerFunction(CastFunction.signature(
        MetapathConstants.NS_METAPATH, "date", IDateItem.class, IDateItem::cast));
    registerFunction(CastFunction.signature(
        MetapathConstants.NS_METAPATH, "date-time", IDateTimeItem.class, IDateTimeItem::cast));
    registerFunction(CastFunction.signature(
        MetapathConstants.NS_METAPATH, "decimal", IDecimalItem.class, IDecimalItem::cast));
    registerFunction(CastFunction.signature(
        MetapathConstants.NS_METAPATH, "duration", IDurationItem.class, IDurationItem::cast));
    registerFunction(CastFunction.signature(
        MetapathConstants.NS_METAPATH, "integer", IIntegerItem.class, IIntegerItem::cast));
    registerFunction(CastFunction.signature(
        MetapathConstants.NS_METAPATH, "ncname", INcNameItem.class, INcNameItem::cast));
    registerFunction(CastFunction.signature(
        MetapathConstants.NS_METAPATH, "non-negative-integer", INonNegativeIntegerItem.class,
        INonNegativeIntegerItem::cast));
    registerFunction(CastFunction.signature(
        MetapathConstants.NS_METAPATH, "positive-integer", IPositiveIntegerItem.class,
        IPositiveIntegerItem::cast));
    registerFunction(CastFunction.signature(
        MetapathConstants.NS_METAPATH, "string", IStringItem.class, IStringItem::cast));

    // extra functions
    registerFunction(MpRecurseDepth.SIGNATURE_ONE_ARG);
    registerFunction(MpRecurseDepth.SIGNATURE_TWO_ARG);
  }

}
