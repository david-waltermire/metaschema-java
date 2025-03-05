/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.function.library;

import gov.nist.secauto.metaschema.core.datatype.DataTypeService;
import gov.nist.secauto.metaschema.core.datatype.IDataTypeAdapter;
import gov.nist.secauto.metaschema.core.metapath.MetapathConstants;
import gov.nist.secauto.metaschema.core.metapath.function.FunctionLibrary;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.INumericItem;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

/**
 * Provides built-in Metapath functions based on the XPath 3.1
 * <a href= "https://www.w3.org/TR/xpath-functions-31/">function
 * specification</a>.
 */
@SuppressFBWarnings("UWF_UNWRITTEN_FIELD")
public class DefaultFunctionLibrary
    extends FunctionLibrary {

  /**
   * Initialize the built-in function library.
   */
  @SuppressFBWarnings(value = "UWF_UNWRITTEN_FIELD", justification = "Static fields used for initialization")
  public DefaultFunctionLibrary() { // NOPMD - intentional
    // https://www.w3.org/TR/xpath-functions-31/#func-abs
    registerFunction(FnAbs.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-adjust-dateTime-to-timezone
    registerFunction(FnAdjustDateTimeToTimezone.ONE_ARG_SIGNATURE);
    registerFunction(FnAdjustDateTimeToTimezone.TWO_ARG_SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-adjust-date-to-timezone
    registerFunction(FnAdjustDateToTimezone.ONE_ARG_SIGNATURE);
    registerFunction(FnAdjustDateToTimezone.TWO_ARG_SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-adjust-time-to-timezone
    registerFunction(FnAdjustTimeToTimezone.ONE_ARG_SIGNATURE);
    registerFunction(FnAdjustTimeToTimezone.TWO_ARG_SIGNATURE);
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
    // https://www.w3.org/TR/xpath-functions-31/#func-contains
    registerFunction(FnContains.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-count
    registerFunction(FnCount.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-current-date
    registerFunction(FnCurrentDate.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-current-dateTime
    registerFunction(FnCurrentDateTime.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-current-time
    registerFunction(FnCurrentTime.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-data
    registerFunction(FnData.SIGNATURE_NO_ARG);
    registerFunction(FnData.SIGNATURE_ONE_ARG);
    // https://www.w3.org/TR/xpath-functions-31/#func-date-time
    registerFunction(FnDateTime.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-day-from-date
    registerFunction(FnDayFromDate.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-day-from-dateTime
    registerFunction(FnDayFromDateTime.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-days-from-duration
    registerFunction(FnDaysFromDuration.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-deep-equal
    registerFunction(FnDeepEqual.SIGNATURE_TWO_ARG);
    // https://www.w3.org/TR/xpath-functions-31/#func-distinct-values
    registerFunction(FnDistinctValues.SIGNATURE_ONE_ARG);
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
    // https://www.w3.org/TR/xpath-functions-31/#func-ends-with
    registerFunction(FnEndsWith.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-exactly-one
    registerFunction(FnExactlyOne.SIGNATURE);
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
    // https://www.w3.org/TR/xpath-functions-31/#func-function-arity
    registerFunction(FnFunctionArity.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-function-lookup
    registerFunction(FnFunctionLookup.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-function-name
    registerFunction(FnFunctionName.SIGNATURE);
    // P1: https://www.w3.org/TR/xpath-functions-31/#func-generate-id
    // https://www.w3.org/TR/xpath-functions-31/#func-has-children
    registerFunction(FnHasChildren.SIGNATURE_NO_ARG);
    registerFunction(FnHasChildren.SIGNATURE_ONE_ARG);
    // https://www.w3.org/TR/xpath-functions-31/#func-head
    registerFunction(FnHead.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-hours-from-dateTime
    registerFunction(FnHoursFromDateTime.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-hours-from-duration
    registerFunction(FnHoursFromDuration.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-hours-from-time
    registerFunction(FnHoursFromTime.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-implicit-timezone
    registerFunction(FnImplicitTimezone.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-index-of
    registerFunction(FnIndexOf.SIGNATURE_TWO_ARG);
    // https://www.w3.org/TR/xpath-functions-31/#func-innermost
    registerFunction(FnInnermost.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-insert-before
    registerFunction(FnInsertBefore.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-iri-to-uri
    // P1: https://www.w3.org/TR/xpath-functions-31/#func-last
    // https://www.w3.org/TR/xpath-functions-31/#func-local-name
    registerFunction(FnLocalName.SIGNATURE_NO_ARG);
    registerFunction(FnLocalName.SIGNATURE_ONE_ARG);
    // https://www.w3.org/TR/xpath-functions-31/#func-lower-case
    registerFunction(FnLowerCase.SIGNATURE_ONE_ARG);
    // https://www.w3.org/TR/xpath-functions-31/#func-matches
    registerFunction(FnMatches.SIGNATURE_TWO_ARG);
    registerFunction(FnMatches.SIGNATURE_THREE_ARG);
    // https://www.w3.org/TR/xpath-functions-31/#func-max
    registerFunction(FnMinMax.SIGNATURE_MAX);
    // https://www.w3.org/TR/xpath-functions-31/#func-min
    registerFunction(FnMinMax.SIGNATURE_MIN);
    // https://www.w3.org/TR/xpath-functions-31/#func-minutes-from-dateTime
    registerFunction(FnMinutesFromDateTime.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-minutes-from-duration
    registerFunction(FnMinutesFromDuration.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-minutes-from-time
    registerFunction(FnMinutesFromTime.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-month-from-date
    registerFunction(FnMonthFromDate.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-month-from-dateTime
    registerFunction(FnMonthFromDateTime.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-months-from-duration
    registerFunction(FnMonthsFromDuration.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-name
    registerFunction(FnName.SIGNATURE_NO_ARG);
    registerFunction(FnName.SIGNATURE_ONE_ARG);
    // https://www.w3.org/TR/xpath-functions-31/#func-namespace-uri
    registerFunction(FnNamespaceUri.SIGNATURE_NO_ARG);
    registerFunction(FnNamespaceUri.SIGNATURE_ONE_ARG);
    // https://www.w3.org/TR/xpath-functions-31/#func-node-name
    // https://www.w3.org/TR/xpath-functions-31/#func-normalize-space
    registerFunction(FnNormalizeSpace.SIGNATURE_NO_ARG);
    registerFunction(FnNormalizeSpace.SIGNATURE_ONE_ARG);
    // https://www.w3.org/TR/xpath-functions-31/#func-normalize-unicode
    // https://www.w3.org/TR/xpath-functions-31/#func-not
    registerFunction(FnNot.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-number
    // https://www.w3.org/TR/xpath-functions-31/#func-one-or-more
    registerFunction(FnOneOrMore.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-outermost
    registerFunction(FnOutermost.SIGNATURE);
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
    // https://www.w3.org/TR/xpath-functions-31/#func-root
    registerFunction(FnRoot.SIGNATURE_NO_ARG);
    registerFunction(FnRoot.SIGNATURE_ONE_ARG);
    // https://www.w3.org/TR/xpath-functions-31/#func-round
    registerFunction(FnRound.SIGNATURE);
    registerFunction(FnRound.SIGNATURE_WITH_PRECISION);
    // P1: https://www.w3.org/TR/xpath-functions-31/#func-round-half-to-even
    // https://www.w3.org/TR/xpath-functions-31/#func-seconds-from-dateTime
    registerFunction(FnSecondsFromDateTime.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-seconds-from-duration
    registerFunction(FnSecondsFromDuration.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-seconds-from-time
    registerFunction(FnSecondsFromTime.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-starts-with
    registerFunction(FnStartsWith.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-static-base-uri
    registerFunction(FnStaticBaseUri.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-string
    registerFunction(FnString.SIGNATURE_NO_ARG);
    registerFunction(FnString.SIGNATURE_ONE_ARG);
    // https://www.w3.org/TR/xpath-functions-30/#func-substring
    registerFunction(FnSubstring.SIGNATURE_TWO_ARG);
    registerFunction(FnSubstring.SIGNATURE_THREE_ARG);
    // P1: https://www.w3.org/TR/xpath-functions-31/#func-string-join
    registerFunction(FnStringJoin.SIGNATURE_ONE_ARG);
    registerFunction(FnStringJoin.SIGNATURE_TWO_ARG);
    // https://www.w3.org/TR/xpath-functions-31/#func-string-length
    registerFunction(FnStringLength.SIGNATURE_NO_ARG);
    registerFunction(FnStringLength.SIGNATURE_ONE_ARG);
    // P1: https://www.w3.org/TR/xpath-functions-31/#func-subsequence
    // https://www.w3.org/TR/xpath-functions-31/#func-substring-after
    registerFunction(FnSubstringAfter.SIGNATURE_TWO_ARG);
    // https://www.w3.org/TR/xpath-functions-31/#func-substring-before
    registerFunction(FnSubstringBefore.SIGNATURE_TWO_ARG);
    // https://www.w3.org/TR/xpath-functions-31/#func-sum
    registerFunction(FnSum.SIGNATURE_ONE_ARG);
    registerFunction(FnSum.SIGNATURE_TWO_ARG);
    // https://www.w3.org/TR/xpath-functions-31/#func-tail
    registerFunction(FnTail.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-timezone-from-date
    registerFunction(FnTimezoneFromDate.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-timezone-from-dateTime
    registerFunction(FnTimezoneFromDateTime.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-timezone-from-time
    registerFunction(FnTimezoneFromTime.SIGNATURE);
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
    // https://www.w3.org/TR/xpath-functions-31/#func-upper-case
    registerFunction(FnUpperCase.SIGNATURE_ONE_ARG);
    // https://www.w3.org/TR/xpath-functions-31/#func-year-from-date
    registerFunction(FnYearFromDate.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-year-from-dateTime
    registerFunction(FnYearFromDateTime.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-years-from-duration
    registerFunction(FnYearsFromDuration.SIGNATURE);
    // https://www.w3.org/TR/xpath-functions-31/#func-zero-or-one
    registerFunction(FnZeroOrOne.SIGNATURE);

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
    // https://www.w3.org/TR/xpath-functions-31/#func-map-for-each
    registerFunction(MapForEach.SIGNATURE);

    // metapath casting functions
    DataTypeService.instance().getDataTypes().stream()
        .map(IDataTypeAdapter::getItemType)
        .forEachOrdered(type -> {
          registerFunction(CastFunction.signature(type.getQName(), type, type::cast));
        });

    // extra functions
    registerFunction(MpRecurseDepth.SIGNATURE_ONE_ARG);
    registerFunction(MpRecurseDepth.SIGNATURE_TWO_ARG);
    registerFunction(MpBase64Decode.SIGNATURE_ONE_ARG);
    registerFunction(MpBase64Encode.SIGNATURE_ONE_ARG);
  }
}
