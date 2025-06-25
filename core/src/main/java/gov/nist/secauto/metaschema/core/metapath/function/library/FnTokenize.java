/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.function.library;

import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.MetapathConstants;
import gov.nist.secauto.metaschema.core.metapath.function.IArgument;
import gov.nist.secauto.metaschema.core.metapath.function.IFunction;
import gov.nist.secauto.metaschema.core.metapath.function.regex.RegexUtil;
import gov.nist.secauto.metaschema.core.metapath.function.regex.RegularExpressionMetapathException;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.ISequence;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IStringItem;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.LinkedList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Implements the XPath 3.1 <a href=
 * "https://www.w3.org/TR/xpath-functions-31/#func-tokenize">fn:tokenize</a>
 * function.
 */
public final class FnTokenize {
  // CPD-OFF
  @NonNull
  private static final String NAME = "tokenize";
  @NonNull
  static final IFunction SIGNATURE_ONE_ARG = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextIndependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("input")
          .type(IStringItem.type())
          .zeroOrOne()
          .build())
      .returnType(IStringItem.type())
      .returnZeroOrMore()
      .functionHandler(FnTokenize::executeOneArg)
      .build();
  @NonNull
  static final IFunction SIGNATURE_TWO_ARG = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextIndependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("input")
          .type(IStringItem.type())
          .zeroOrOne()
          .build())
      .argument(IArgument.builder()
          .name("pattern")
          .type(IStringItem.type())
          .one()
          .build())
      .returnType(IStringItem.type())
      .returnZeroOrMore()
      .functionHandler(FnTokenize::executeTwoArg)
      .build();

  @NonNull
  static final IFunction SIGNATURE_THREE_ARG = IFunction.builder()
      .name(NAME)
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS)
      .deterministic()
      .contextIndependent()
      .focusIndependent()
      .argument(IArgument.builder()
          .name("input")
          .type(IStringItem.type())
          .zeroOrOne()
          .build())
      .argument(IArgument.builder()
          .name("pattern")
          .type(IStringItem.type())
          .one()
          .build())
      .argument(IArgument.builder()
          .name("flags")
          .type(IStringItem.type())
          .one()
          .build())
      .returnType(IStringItem.type())
      .returnZeroOrMore()
      .functionHandler(FnTokenize::executeThreeArg)
      .build();
  // CPD-ON

  @SuppressWarnings({ "unused" })
  @NonNull
  private static ISequence<IStringItem> executeOneArg(
      @NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    IStringItem input = IStringItem.type().ofTypeOrNull(arguments.get(0).getFirstItem(true));

    return input == null
        ? ISequence.empty()
        : ISequence.of(ObjectUtils.notNull(
            fnTokenize(input.normalizeSpace().asString(), " ", "").stream()
                .map(IStringItem::valueOf)));
  }

  @SuppressWarnings({ "unused" })
  @NonNull
  private static ISequence<IStringItem> executeTwoArg(
      @NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    IStringItem input = IStringItem.type().ofTypeOrNull(arguments.get(0).getFirstItem(true));
    IStringItem pattern = IStringItem.type().ofType(arguments.get(1).getFirstItem(true));

    return execute(input, pattern, IStringItem.valueOf(""));
  }

  @SuppressWarnings({ "unused" })
  @NonNull
  private static ISequence<IStringItem> executeThreeArg(
      @NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {

    IStringItem input = IStringItem.type().ofTypeOrNull(arguments.get(0).getFirstItem(true));
    IStringItem pattern = IStringItem.type().ofType(arguments.get(1).getFirstItem(true));
    IStringItem flags = IStringItem.type().ofType(arguments.get(2).getFirstItem(true));

    return execute(input, pattern, flags);
  }

  @NonNull
  private static ISequence<IStringItem> execute(
      @Nullable IStringItem input,
      @NonNull IStringItem pattern,
      @NonNull IStringItem flags) {
    return input == null
        ? ISequence.empty()
        : fnTokenize(input, pattern, flags);
  }

  /**
   * Implements <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-tokenize">fn:tokenize</a>.
   *
   * @param input
   *          the string to tokenize
   * @param pattern
   *          the regular expression to use for identifying token boundaries
   * @param flags
   *          matching options
   * @return the sequence of tokens
   */
  @NonNull
  public static ISequence<IStringItem> fnTokenize(
      @NonNull IStringItem input,
      @NonNull IStringItem pattern,
      @NonNull IStringItem flags) {
    return ISequence.of(ObjectUtils.notNull(
        fnTokenize(input.asString(), pattern.asString(), flags.asString()).stream()
            .map(IStringItem::valueOf)));
  }

  /**
   * Implements <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-tokenize">fn:tokenize</a>.
   *
   * @param input
   *          the string to match against
   * @param pattern
   *          the regular expression to use for matching
   * @param flags
   *          matching options
   * @return the stream of tokens
   */
  @SuppressWarnings({ "PMD.OnlyOneReturn", "PMD.CyclomaticComplexity" })
  @NonNull
  public static List<String> fnTokenize(@NonNull String input, @NonNull String pattern, @NonNull String flags) {
    if (input.isEmpty()) {
      return CollectionUtil.emptyList();
    }

    try {
      Matcher matcher = Pattern.compile(pattern, RegexUtil.parseFlags(flags)).matcher(input);

      int lastPosition = 0;
      int length = input.length();

      List<String> result = new LinkedList<>();
      while (matcher.find()) {
        String group = matcher.group();
        if (group.isEmpty()) {
          throw new RegularExpressionMetapathException(RegularExpressionMetapathException.MATCHES_ZERO_LENGTH_STRING,
              String.format("Pattern '%s' will match a zero-length string.", pattern));
        }

        int start = matcher.start();
        if (start == 0) {
          result.add("");
        } else {
          result.add(input.substring(lastPosition, start));
        }

        lastPosition = matcher.end();
      }

      if (lastPosition == length) {
        result.add("");
      } else {
        result.add(input.substring(lastPosition, length));
      }

      return result;
    } catch (PatternSyntaxException ex) {
      throw new RegularExpressionMetapathException(RegularExpressionMetapathException.INVALID_EXPRESSION, ex);
    } catch (IllegalArgumentException ex) {
      throw new RegularExpressionMetapathException(RegularExpressionMetapathException.INVALID_FLAG, ex);
    }
  }

  private FnTokenize() {
    // disable construction
  }
}
