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

package gov.nist.secauto.metaschema.databind.model.info;

import gov.nist.secauto.metaschema.core.util.CollectionUtil;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;
import gov.nist.secauto.metaschema.databind.io.BindingException;
import gov.nist.secauto.metaschema.databind.model.IBoundInstanceModel;
import gov.nist.secauto.metaschema.databind.model.IBoundObject;

import java.io.IOException;
import java.lang.reflect.ParameterizedType;
import java.util.LinkedList;
import java.util.List;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

class ListCollectionInfo<ITEM>
    extends AbstractModelInstanceCollectionInfo<ITEM> {

  public ListCollectionInfo(
      @NonNull IBoundInstanceModel<ITEM> instance) {
    super(instance);
  }

  @SuppressWarnings("unchecked")
  @Override
  public Class<? extends ITEM> getItemType() {
    ParameterizedType actualType = (ParameterizedType) getInstance().getType();
    // this is a List so there is only a single generic type
    return ObjectUtils.notNull((Class<? extends ITEM>) actualType.getActualTypeArguments()[0]);
  }

  @Override
  public List<ITEM> getItemsFromParentInstance(Object parentInstance) {
    Object value = getInstance().getValue(parentInstance);
    return getItemsFromValue(value);
  }

  @SuppressWarnings("unchecked")
  @Override
  public List<ITEM> getItemsFromValue(Object value) {
    return value == null ? CollectionUtil.emptyList() : (List<ITEM>) value;
  }

  @Override
  public int size(Object value) {
    return value == null ? 0 : ((List<?>) value).size();
  }

  @Override
  public boolean isEmpty(@Nullable Object value) {
    return value == null || ((List<?>) value).isEmpty();
  }

  @Override
  public List<ITEM> deepCopyItems(@NonNull IBoundObject fromInstance, @NonNull IBoundObject toInstance)
      throws BindingException {
    IBoundInstanceModel<ITEM> instance = getInstance();

    List<ITEM> copy = emptyValue();
    for (ITEM item : getItemsFromParentInstance(fromInstance)) {
      copy.add(instance.deepCopyItem(ObjectUtils.requireNonNull(item), toInstance));
    }
    return copy;
  }

  @Override
  public List<ITEM> emptyValue() {
    return new LinkedList<>();
  }

  @Override
  public List<ITEM> readItems(IModelInstanceReadHandler<ITEM> handler) throws IOException {
    return handler.readList();
  }

  @SuppressWarnings("unchecked")
  @Override
  public void writeItems(IModelInstanceWriteHandler<ITEM> handler, Object value) throws IOException {
    handler.writeList((List<ITEM>) value);
  }
}
