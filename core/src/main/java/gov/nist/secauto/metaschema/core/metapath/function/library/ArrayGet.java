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

package gov.nist.secauto.metaschema.core.metapath.function.library;

import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.ISequence;
import gov.nist.secauto.metaschema.core.metapath.MetapathConstants;
import gov.nist.secauto.metaschema.core.metapath.function.FunctionUtils;
import gov.nist.secauto.metaschema.core.metapath.function.IArgument;
import gov.nist.secauto.metaschema.core.metapath.function.IFunction;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IIntegerItem;
import gov.nist.secauto.metaschema.core.metapath.item.function.IArrayItem;
import gov.nist.secauto.metaschema.core.metapath.item.function.IArrayMember;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.ArrayList;
import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;

public class ArrayGet {
  @NonNull
  static final IFunction SIGNATURE = IFunction.builder()
      .name("size")
      .namespace(MetapathConstants.NS_METAPATH_FUNCTIONS_ARRAY)
      .argument(IArgument.builder()
          .name("array")
          .type(IArrayItem.class)
          .one()
          .build())
      .argument(IArgument.builder()
          .name("position")
          .type(IIntegerItem.class)
          .one()
          .build())
      .returnType(IIntegerItem.class)
      .returnZeroOrMore()
      .functionHandler(ArrayGet::execute)
      .build();

  @SuppressWarnings("unused")
  @NonNull
  private static ISequence<IIntegerItem> execute(@NonNull IFunction function,
      @NonNull List<ISequence<?>> arguments,
      @NonNull DynamicContext dynamicContext,
      IItem focus) {
    IArrayItem<?> array = FunctionUtils.asType(ObjectUtils.requireNonNull(arguments.get(0).getFirstItem(true)));
    IIntegerItem position = FunctionUtils.asType(ObjectUtils.requireNonNull(arguments.get(1).getFirstItem(true)));

    if (position < 1) {
      position = 1;
    } else if (position > target.size()) {
      position = target.size() + 1;
    }

    return ISequence.of(IIntegerItem.valueOf(array.size()));
  }

  /**
   * An implementation of XPath 3.1 <a href=
   * "https://www.w3.org/TR/xpath-functions-31/#func-array-get">array:get</a>.
   *
   * @param <T>
   *          the type for the given Metapath sequence
   * @param target
   *          the sequence of Metapath items that is the target of insertion
   * @param positionItem
   *          the integer position of the item to insert before
   * @return the sequence of Metapath items with insertions
   */
  @SuppressWarnings("PMD.OnlyOneReturn")
  @NonNull
  public static <T extends IItem> List<T> get(
      @NonNull List<T> target,
      @NonNull IIntegerItem positionItem) {
    int position = positionItem.asInteger().intValue();

    if (position < 1 || position > target.size()) {
    }

    IArrayMember member = target.get(position - 1);

    List<T> newSequence = new ArrayList<>(target.size());

    if (position == 1) {
      newSequence.addAll(inserts);
      newSequence.addAll(target);
    } else {
      newSequence.addAll(target.subList(0, position - 1));
      newSequence.addAll(inserts);
      newSequence.addAll(target.subList(position - 1, target.size()));
    }
    return newSequence;
  }
}
