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

package gov.nist.secauto.metaschema.core.model.constraint;

import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.InvalidTypeMetapathException;
import gov.nist.secauto.metaschema.core.metapath.MetapathException;
import gov.nist.secauto.metaschema.core.metapath.MetapathExpression;
import gov.nist.secauto.metaschema.core.metapath.MetapathExpression.ResultType;
import gov.nist.secauto.metaschema.core.metapath.function.library.FnData;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.INodeItem;
import gov.nist.secauto.metaschema.core.model.constraint.impl.DefaultIndex;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

public interface IIndex {

  /**
   * Construct a new index using the provided key field components to generate
   * keys.
   *
   * @param keyFields
   *          the key field components to use to generate keys by default
   * @return the new index
   */
  @NonNull
  static IIndex newInstance(@NonNull List<? extends IKeyField> keyFields) {
    return new DefaultIndex(keyFields);
  }

  /**
   * Check if a key contains information other than {@code null} Strings.
   *
   * @param key
   *          the key to check
   * @return {@code true} if the series of key values contains only {@code null}
   *         values, or {@code false} otherwise
   */
  static boolean isAllNulls(@NonNull Iterable<String> key) {
    for (String value : key) {
      if (value != null) {
        return false; // NOPMD readability
      }
    }
    return true;
  }

  /**
   * Retrieve the key field components used to generate a key for this index.
   *
   * @return the key field components
   */
  @NonNull
  List<IKeyField> getKeyFields();

  /**
   * Store the provided item in the index using the index's key field components
   * to generate the key.
   *
   * @param item
   *          the item to store in the index
   * @param dynamicContext
   *          the Metapath evaluation context
   * @return the previous item stored in the index, or {@code null} otherwise
   */
  @Nullable
  default INodeItem put(@NonNull INodeItem item, @NonNull DynamicContext dynamicContext) {
    List<String> key = toKey(item, getKeyFields(), dynamicContext);
    return put(item, key);
  }

  /**
   * Store the provided item using the provided key.
   *
   * @param item
   *          the item to store
   * @param key
   *          the key to store the item with
   * @return the previous item stored in the index using the key, or {@code null}
   *         otherwise
   */
  @Nullable
  INodeItem put(@NonNull INodeItem item, @NonNull List<String> key);

  /**
   * Retrieve the item from the index that matches the key generated by evaluating
   * the index's default key field components against the provided item.
   *
   * @param item
   *          the item to store in the index
   * @param dynamicContext
   *          the Metapath evaluation context
   * @return the previous item stored in the index, or {@code null} otherwise
   */
  @Nullable
  default INodeItem get(@NonNull INodeItem item, @NonNull DynamicContext dynamicContext) {
    List<String> key = toKey(item, getKeyFields(), dynamicContext);
    return get(key);
  }

  /**
   * Retrieve the item from the index that matches the provided key.
   *
   * @param key
   *          the key to use for lookup
   * @return the item with the matching key or {@code null} if no matching item
   *         was found
   */
  INodeItem get(List<String> key);

  /**
   * Construct a key by evaluating the provided key field components against the
   * provided item.
   *
   * @param item
   *          the item to generate the key from
   * @param keyFields
   *          the key field components used to generate the key
   * @param dynamicContext
   *          the Metapath evaluation context
   * @return a new key
   */
  @NonNull
  static List<String> toKey(@NonNull INodeItem item, @NonNull List<? extends IKeyField> keyFields,
      @NonNull DynamicContext dynamicContext) {
    return CollectionUtil.unmodifiableList(
        ObjectUtils.notNull(keyFields.stream()
            .map(keyField -> {
              assert keyField != null;
              return buildKeyItem(item, keyField, dynamicContext);
            })
            .collect(Collectors.toCollection(ArrayList::new))));
  }

  /**
   * Evaluates the provided key field component against the item to generate a key
   * value.
   *
   * @param item
   *          the item to generate the key value from
   * @param keyField
   *          the key field component used to generate the key value
   * @param dynamicContext
   *          the Metapath evaluation context
   * @return the key value or {@code null} if the evaluation resulted in no value
   */
  @Nullable
  private static String buildKeyItem(
      @NonNull INodeItem item,
      @NonNull IKeyField keyField,
      @NonNull DynamicContext dynamicContext) {
    String keyPath = keyField.getTarget();
    MetapathExpression keyMetapath = MetapathExpression.compile(keyPath, dynamicContext.getStaticContext());

    IItem keyItem;
    try {
      keyItem = keyMetapath.evaluateAs(item, ResultType.ITEM, dynamicContext);
    } catch (InvalidTypeMetapathException ex) {
      throw new MetapathException("Key path did not result in a single item", ex);
    }

    String keyValue = null;
    if (keyItem != null) {
      keyValue = FnData.fnDataItem(keyItem).asString();
      assert keyValue != null;
      Pattern pattern = keyField.getPattern();
      if (pattern != null) {
        keyValue = applyPattern(keyMetapath, keyValue, pattern);
      }
    } // empty key
    return keyValue;
  }

  /**
   * Apply the key value pattern, if configured, to generate the final key value.
   *
   * @param keyItem
   *          the node item used to form the key field
   * @param pattern
   *          the key field pattern configuration from the constraint
   * @param keyValue
   *          the current key value
   * @return the final key value
   */
  private static String applyPattern(@NonNull MetapathExpression keyMetapath, @NonNull String keyValue,
      @NonNull Pattern pattern) {
    Matcher matcher = pattern.matcher(keyValue);
    if (!matcher.matches()) {
      throw new MetapathException(
          String.format("Key field declares the pattern '%s' which does not match the value '%s' of node '%s'",
              pattern.pattern(), keyValue, keyMetapath));
    }

    if (matcher.groupCount() != 1) {
      throw new MetapathException(String.format(
          "The first group was not a match for value '%s' of node '%s' for key field pattern '%s'",
          keyValue, keyMetapath, pattern.pattern()));
    }
    return matcher.group(1);
  }
}
